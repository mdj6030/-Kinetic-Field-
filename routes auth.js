// ============================================================
//  Kinetic Field — دوال المصادقة والجلسات (Auth & Sessions)
//
//  1) login: يتحقق من بيانات الدخول (bcrypt)، يولّد session_token
//     عشوائياً آمناً، ويُجري UPSERT على active_sessions — فيستبدل أي
//     جلسة سابقة ويطرد الجهاز القديم تلقائياً (توكنه لم يعد يطابق).
//  2) logout: يحذف الجلسة النشطة.
//
//  ملاحظة: session_token عشوائي (لا JWT) عمداً — ليكون قابلاً للإبطال
//  الفوري، وهو جوهر الجلسة الواحدة.
// ============================================================

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { pool } = require('../lib/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

function newSessionToken() {
  // UUID v4 عشوائي تشفيرياً (يطابق نوع session_token UUID في المخطط).
  return crypto.randomUUID();
}

// ---------- تسجيل الدخول ----------
router.post('/login', async (req, res) => {
  const { phone, email, password, deviceFingerprint, deviceLabel } = req.body || {};
  if ((!phone && !email) || !password) {
    return res.status(400).json({ error: 'missing_credentials' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, role, password_hash, is_active
         FROM users
        WHERE ($1::text IS NOT NULL AND phone = $1)
           OR ($2::citext IS NOT NULL AND email = $2)
        LIMIT 1`,
      [phone || null, email || null]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const user = rows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'account_disabled' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // توليد التوكن واستبدال الجلسة (طرد الجهاز القديم).
    const token = newSessionToken();
    await pool.query(
      `INSERT INTO active_sessions
         (user_id, session_token, device_fingerprint, device_label, ip_address, issued_at, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, now(), now())
       ON CONFLICT (user_id) DO UPDATE
         SET session_token = EXCLUDED.session_token,
             device_fingerprint = EXCLUDED.device_fingerprint,
             device_label = EXCLUDED.device_label,
             ip_address = EXCLUDED.ip_address,
             issued_at = now(),
             last_seen_at = now()`,
      [user.id, token, deviceFingerprint || null, deviceLabel || null,
       req.ip || null]
    );

    res.json({
      sessionToken: token,
      userId: user.id,
      role: user.role,
    });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ---------- تسجيل الخروج ----------
router.post('/logout', authenticate, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM active_sessions WHERE user_id = $1 AND session_token = $2`,
      [req.user.id, req.user.token]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('logout error', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

module.exports = router;
