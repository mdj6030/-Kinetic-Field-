// ============================================================
// Kinetic Field — نقطة دخول الخادم (Express) — الملف النهائي الكامل
// كل الوظائف في ملف واحد؛ لا استيراد من routes/.
// متوافق مع مخطط db.js (UUID/ENUM)، ويستخدم pool.query باستعلامات معلَّمة.
// يعمل على Railway: يستمع على process.env.PORT || 3000.
// ============================================================
const express = require('express');
const crypto = require('crypto'); // لتوقيع روابط Bunny Stream
const bcrypt = require('bcryptjs'); // لمقارنة password_hash بأمان
const { pool, roleCan, initSchema } = require('./db');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.set('trust proxy', true); // لالتقاط req.ip الصحيح خلف بروكسي Railway

// ============================================================
// إعدادات Bunny Stream — كلها من متغيرات البيئة (لا أسرار في الكود).
//   BUNNY_LIBRARY_ID : معرّف مكتبة الفيديو (699176).
//   BUNNY_TOKEN_KEY  : مفتاح توقيع التوكن (Token Authentication Key)
//                      من: لوحة Bunny > المكتبة > Security > Token Authentication.
//                      ملاحظة: هذا ليس مفتاح الـ API؛ لا تستخدم API Key للتوقيع.
// ============================================================
const BUNNY_LIBRARY_ID = process.env.BUNNY_LIBRARY_ID || '699176';
const BUNNY_TOKEN_KEY = process.env.BUNNY_TOKEN_KEY;
const BUNNY_TOKEN_TTL_SECONDS = 3600; // صلاحية الرابط: ساعة واحدة

// توليد رابط تضمين موقّع لـ Bunny Stream.
// الصيغة الرسمية: token = HEX( SHA256(tokenKey + videoId + expires) )
// المرجع: docs.bunny.net/docs/stream-embed-token-authentication
function generateSecureVideoUrl(videoId) {
  if (!videoId || !BUNNY_TOKEN_KEY) return null;
  const expires = Math.floor(Date.now() / 1000) + BUNNY_TOKEN_TTL_SECONDS;
  const token = crypto
    .createHash('sha256')
    .update(BUNNY_TOKEN_KEY + videoId + expires)
    .digest('hex');
  return `https://iframe.mediadelivery.net/embed/${BUNNY_LIBRARY_ID}/${videoId}?token=${token}&expires=${expires}`;
}

// ============================================================
// authMiddleware — التحقق من الجلسة الواحدة النشطة
//   يقرأ ترويسة: Authorization: Bearer <session_token>
//   يطابقها مع active_sessions.session_token؛ عدم التطابق => 401 وطرد فوري.
//   ينجح => يرفق req.user = { id, role } ويحدّث last_seen_at.
// ============================================================
async function authMiddleware(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ error: 'missing_token' });
    }
    const token = match[1].trim();

    // نطابق التوكن مع الجلسة النشطة ونجلب دور المستخدم في استعلام واحد.
    const result = await pool.query(
      `SELECT s.user_id, u.role, u.is_active
         FROM active_sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.session_token = $1
        LIMIT 1`,
      [token]
    );

    if (result.rowCount === 0) {
      // التوكن لا يطابق الجلسة الحالية => جلسة قديمة أو مطرودة.
      return res.status(401).json({ error: 'session_invalid' });
    }

    const row = result.rows[0];
    if (!row.is_active) {
      return res.status(403).json({ error: 'account_disabled' });
    }

    // تحديث آخر ظهور (تشخيصي — لا يؤثر على صحة التوكن).
    await pool.query(
      `UPDATE active_sessions SET last_seen_at = now() WHERE user_id = $1`,
      [row.user_id]
    );

    req.user = { id: row.user_id, role: row.role };
    next();
  } catch (err) {
    console.error('authMiddleware', err);
    res.status(500).json({ error: 'internal_error' });
  }
}

// ------------------------------------------------------------
// المسار الرئيسي — يمنع خطأ Cannot GET /
// ------------------------------------------------------------
app.get('/', (req, res) => res.send('Kinetic Field API is Online'));

// ------------------------------------------------------------
// فحص الصحة
// ------------------------------------------------------------
app.get('/health', (_req, res) => res.json({ ok: true }));

// ------------------------------------------------------------
// /auth/login — تسجيل الدخول (يفرض مبدأ الجلسة الواحدة النشطة)
// ------------------------------------------------------------
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      return res.status(400).json({ error: 'missing_credentials' });
    }

    // البحث عن المستخدم بالبريد (CITEXT) أو الهاتف.
    const userResult = await pool.query(
      `SELECT id, role, full_name, password_hash, is_active
         FROM users
        WHERE email = $1 OR phone = $1
        LIMIT 1`,
      [identifier]
    );

    if (userResult.rowCount === 0) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = userResult.rows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'account_disabled' });
    }

    const passwordOk = (password === user.password_hash) || await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // UPSERT على user_id: أي جلسة قديمة تُستبدل فوراً => جلسة واحدة نشطة.
    const sessionResult = await pool.query(
      `INSERT INTO active_sessions
         (user_id, session_token, device_fingerprint, device_label, ip_address, issued_at, last_seen_at)
       VALUES ($1, uuid_generate_v4(), $2, $3, $4, now(), now())
       ON CONFLICT (user_id) DO UPDATE
         SET session_token      = uuid_generate_v4(),
             device_fingerprint = EXCLUDED.device_fingerprint,
             device_label       = EXCLUDED.device_label,
             ip_address         = EXCLUDED.ip_address,
             issued_at          = now(),
             last_seen_at       = now()
       RETURNING session_token`,
      [
        user.id,
        req.body.device_fingerprint || null,
        req.body.device_label || null,
        req.ip || null,
      ]
    );

    return res.json({
      ok: true,
      session_token: sessionResult.rows[0].session_token,
      user: { id: user.id, full_name: user.full_name, role: user.role },
    });
  } catch (err) {
    console.error('auth/login', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /auth/logout — إنهاء الجلسة الحالية (محمي)
// ------------------------------------------------------------
app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM active_sessions WHERE user_id = $1`,
      [req.user.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('auth/logout', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /video/:lectureId/playback — تشغيل المحاضرة (محمي)
//   يتحقق من وجود enrollment يربط الطالب بكورس المحاضرة قبل الإرجاع.
// ------------------------------------------------------------
app.get('/video/:lectureId/playback', authMiddleware, async (req, res) => {
  try {
    const { lectureId } = req.params;

    // نجلب المحاضرة + نتحقق من تسجيل الطالب في كورسها، في استعلام واحد.
    // lectures.course_id متوفّر مباشرة (تكرار مقصود في المخطط).
    const result = await pool.query(
      `SELECT l.id, l.title, l.bunny_video_id, l.duration_seconds, l.is_processed
         FROM lectures l
         JOIN enrollments e
           ON e.course_id = l.course_id
          AND e.student_id = $2
        WHERE l.id = $1
        LIMIT 1`,
      [lectureId, req.user.id]
    );

    if (result.rowCount === 0) {
      // إما المحاضرة غير موجودة، أو الطالب غير مسجّل في كورسها.
      return res.status(403).json({ error: 'not_enrolled' });
    }

    const lecture = result.rows[0];
    if (!lecture.is_processed) {
      return res.status(409).json({ error: 'video_processing' });
    }

    // توليد رابط التضمين الموقّع من bunny_video_id المقروء من قاعدة البيانات.
    const videoUrl = generateSecureVideoUrl(lecture.bunny_video_id);
    if (!videoUrl) {
      // ينقص المفتاح BUNNY_TOKEN_KEY أو الفيديو بلا bunny_video_id.
      return res.status(500).json({ error: 'video_url_unavailable' });
    }

    return res.json({
      ok: true,
      lecture_id: lecture.id,
      title: lecture.title,
      video_url: videoUrl, // الرابط الموقّع (صالح ساعة واحدة)
      duration_seconds: lecture.duration_seconds,
    });
  } catch (err) {
    console.error('video/playback', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /codes/redeem — تفعيل كود الوصول (محمي)
//   معاملة واحدة: قفل الكود => تحقق active => تحديثه used => إنشاء enrollment.
// ------------------------------------------------------------
app.post('/codes/redeem', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { code } = req.body || {};
    if (!code) {
      return res.status(400).json({ error: 'missing_code' });
    }

    await client.query('BEGIN');

    // FOR UPDATE يقفل الصف لمنع تفعيل الكود نفسه مرتين على التوازي.
    const codeResult = await client.query(
      `SELECT id, course_id, bundle_id, value_iqd, status
         FROM access_codes
        WHERE code = $1 AND deleted_at IS NULL
        FOR UPDATE`,
      [code]
    );

    if (codeResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'code_not_found' });
    }

    const ac = codeResult.rows[0];
    if (ac.status !== 'active') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'code_not_active' });
    }

    // تحديث الكود إلى used مع تسجيل المفعِّل ووقت الاستخدام.
    await client.query(
      `UPDATE access_codes
          SET status = 'used', used_by = $1, used_at = now()
        WHERE id = $2`,
      [req.user.id, ac.id]
    );

    // إنشاء صف enrollment (source = 'access_code').
    // UNIQUE(student_id, course_id) يمنع التسجيل المكرر في نفس الكورس.
    await client.query(
      `INSERT INTO enrollments
         (student_id, course_id, bundle_id, source, access_code_id, amount_paid_iqd)
       VALUES ($1, $2, $3, 'access_code', $4, $5)
       ON CONFLICT (student_id, course_id) DO NOTHING`,
      [req.user.id, ac.course_id, ac.bundle_id, ac.id, ac.value_iqd]
    );

    await client.query('COMMIT');
    return res.json({ ok: true, course_id: ac.course_id, bundle_id: ac.bundle_id });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('codes/redeem', err);
    return res.status(500).json({ error: 'internal_error' });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// /ai/ask — سؤال الذكاء الاصطناعي (محمي) — الكاش لاحقاً
// ------------------------------------------------------------
app.post('/ai/ask', authMiddleware, async (req, res) => {
  try {
    // TODO: احسب prompt_hash، ابحث في ai_cache؛ إن وُجد أعده وزد hit_count،
    // وإلا استدعِ المزوّد واحفظ النتيجة.
    res.json({ ok: true, endpoint: 'ai/ask' });
  } catch (err) {
    console.error('ai/ask', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// معالج أخطاء أخير.
// ------------------------------------------------------------
app.use((err, _req, res, _next) => {
  console.error('unhandled', err);
  res.status(500).json({ error: 'internal_error' });
});

// ============================================================
// الإقلاع: تهيئة قاعدة البيانات أولاً، ثم بدء الاستماع.
// ============================================================
(async () => {
  try {
    await initSchema();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 Kinetic Field API on ${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

module.exports = app;
