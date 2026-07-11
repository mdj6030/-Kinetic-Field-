// ============================================================
// Kinetic Field — نقطة دخول الخادم (Express) — الملف النهائي الكامل
// كل الوظائف في ملف واحد؛ لا استيراد من routes/.
// متوافق مع مخطط db.js (UUID/ENUM)، ويستخدم pool.query باستعلامات معلَّمة.
// يعمل على Railway: يستمع على process.env.PORT || 3000.
// ============================================================
const express = require('express');
const crypto = require('crypto'); // لتوقيع روابط Bunny Stream والتحقق من الـ Webhook
const bcrypt = require('bcryptjs'); // لمقارنة password_hash بأمان
const axios = require('axios'); // لإرسال الطلبات لـ Bunny API
const { pool, roleCan, initSchema } = require('./db');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.set('trust proxy', true); // لالتقاط req.ip الصحيح خلف بروكسي Railway

// ============================================================
// إعدادات Bunny Stream — كلها من متغيرات البيئة (لا أسرار في الكود).
//   BUNNY_STREAM_LIBRARY_ID : معرّف مكتبة الفيديو (699176).
//   BUNNY_TOKEN_KEY         : مفتاح توقيع التوكن للمشاهدة الآمنة.
//   BUNNY_ACCOUNT_API_KEY   : المفتاح الرئيسي للحساب المستخدم في الرفع.
// ============================================================
const BUNNY_LIBRARY_ID = process.env.BUNNY_STREAM_LIBRARY_ID || '699176';
const BUNNY_TOKEN_KEY = process.env.BUNNY_TOKEN_KEY;
const BUNNY_ACCOUNT_API_KEY = process.env.BUNNY_ACCOUNT_API_KEY;
const BUNNY_TOKEN_TTL_SECONDS = 3600; // صلاحية الرابط: ساعة واحدة

// توليد رابط تضمين موقّع لـ Bunny Stream.
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
// ============================================================
async function authMiddleware(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ error: 'missing_token' });
    }
    const token = match[1].trim();

    const result = await pool.query(
      `SELECT s.user_id, u.role, u.is_active
         FROM active_sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.session_token = $1
        LIMIT 1`,
      [token]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: 'session_invalid' });
    }

    const row = result.rows[0];
    if (!row.is_active) {
      return res.status(403).json({ error: 'account_disabled' });
    }

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
// المسار الرئيسي وفحص الصحة
// ------------------------------------------------------------
app.get('/', (req, res) => res.send('Kinetic Field API is Online'));
app.get('/health', (_req, res) => res.json({ ok: true }));

// ------------------------------------------------------------
// /auth/login — تسجيل الدخول
// ------------------------------------------------------------
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      return res.status(400).json({ error: 'missing_credentials' });
    }

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
// /auth/logout — إنهاء الجلسة
// ------------------------------------------------------------
app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    await pool.query(`DELETE FROM active_sessions WHERE user_id = $1`, [req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('auth/logout', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// [مأخوذ من كلوود] /videos/create-upload — تجهيز الرفع التلقائي للمدرسين لـ TUS
// ------------------------------------------------------------
app.post('/videos/create-upload', authMiddleware, async (req, res) => {
  try {
    // التأكد من أن المستخدم مدرس أو مدير
    if (req.user.role !== 'instructor' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'unauthorized_role' });
    }

    const { title, course_id, section_id, description } = req.body;
    if (!title || !course_id || !section_id) {
      return res.status(400).json({ error: 'missing_required_fields' });
    }

    // 1. إنشاء فيديو فارغ في Bunny لجلب الـ Video ID تلقائياً
    const bunnyRes = await axios.post(
      `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos`,
      { title: title },
      { headers: { AccessKey: BUNNY_ACCOUNT_API_KEY } }
    );

    const bunnyVideoId = bunnyRes.data.guid;

    // 2. إدخال المحاضرة في قاعدة البيانات تلقائياً وتثبيت الـ ID وحالتها معلقة (false)
    const dbRes = await pool.query(
      `INSERT INTO lectures (course_id, section_id, title, description, bunny_video_id, is_processed)
       VALUES ($1, $2, $3, $4, $5, false)
       RETURNING id`,
      [course_id, section_id, title, description || null, bunnyVideoId]
    );

    // 3. توليد كود التوقيع لبروتوكول TUS ليرفع تطبيق المدرس مباشرة لـ Bunny دون وسيط
    const expireTime = Math.floor(Date.now() / 1000) + 86400; // صلاحية 24 ساعة للرفع
    const signature = crypto
      .createHash('sha256')
      .update(BUNNY_LIBRARY_ID + BUNNY_ACCOUNT_API_KEY + expireTime + bunnyVideoId)
      .digest('hex');

    return res.json({
      ok: true,
      lectureId: dbRes.rows[0].id,
      tus: {
        endpoint: 'https://video.bunnycdn.com/tusupload',
        headers: {
          AuthorizationSignature: signature,
          AuthorizationExpire: expireTime,
          VideoId: bunnyVideoId,
          LibraryId: BUNNY_LIBRARY_ID,
        },
      },
    });
  } catch (err) {
    console.error('videos/create-upload', err.message);
    return res.status(500).json({ error: 'failed_to_initialize_upload' });
  }
});

// ------------------------------------------------------------
// [مأخوذ من كلوود] /videos/webhook — التحديث التلقائي الفوري من Bunny عند انتهاء المعالجة
// ------------------------------------------------------------
app.post('/videos/webhook', async (req, res) => {
  try {
    const videoGuid = req.body?.VideoGuid || req.body?.videoGuid;
    const status = req.body?.Status ?? req.body?.status;

    if (!videoGuid) return res.status(400).json({ error: 'missing_guid' });

    // في Bunny Stream، الحالة 3 أو 4 تعني أن الفيديو انتهى من المعالجة وجاهز تماماً
    const ready = Number(status) === 4 || Number(status) === 3;
    if (ready) {
      // جلب مدة الفيديو الفعلية لتحديث قاعدة البيانات
      let duration = null;
      try {
        const info = await axios.get(
          `https://video.bunnycdn.com/library/${BUNNY_LIBRARY_ID}/videos/${videoGuid}`,
          { headers: { AccessKey: BUNNY_ACCOUNT_API_KEY } }
        );
        if (info.data && info.data.length) {
          duration = Math.round(info.data.length); // بالثواني
        }
      } catch (_) {}

      // تحديث حالة المحاضرة تلقائياً لـ TRUE وحفظ المدة لتصبح متاحة للطلاب فوراً!
      await pool.query(
        `UPDATE lectures 
         SET is_processed = true,
             duration_seconds = COALESCE($2, duration_seconds)
         WHERE bunny_video_id = $1`,
        [videoGuid, duration]
      );
      console.log(`✅ Video ${videoGuid} updated to active automatically via Webhook.`);
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('videos/webhook error', err);
    return res.status(500).json({ error: 'webhook_failed' });
  }
});

// ------------------------------------------------------------
// /video/:lectureId/playback — تشغيل المحاضرة (محمي)
// ------------------------------------------------------------
app.get('/video/:lectureId/playback', authMiddleware, async (req, res) => {
  try {
    const { lectureId } = req.params;

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
      return res.status(403).json({ error: 'not_enrolled' });
    }

    const lecture = result.rows[0];
    if (!lecture.is_processed) {
      return res.status(409).json({ error: 'video_processing' });
    }

    const videoUrl = generateSecureVideoUrl(lecture.bunny_video_id);
    if (!videoUrl) {
      return res.status(500).json({ error: 'video_url_unavailable' });
    }

    return res.json({
      ok: true,
      lecture_id: lecture.id,
      title: lecture.title,
      video_url: videoUrl,
      duration_seconds: lecture.duration_seconds,
    });
  } catch (err) {
    console.error('video/playback', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /codes/redeem — تفعيل كود الوصول (محمي)
// ------------------------------------------------------------
app.post('/codes/redeem', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { code } = req.body || {};
    if (!code) {
      return res.status(400).json({ error: 'missing_code' });
    }

    await client.query('BEGIN');

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

    await client.query(
      `UPDATE access_codes
          SET status = 'used', used_by = $1, used_at = now()
        WHERE id = $2`,
      [req.user.id, ac.id]
    );

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
// /ai/ask — سؤال الذكاء الاصطناعي
// ------------------------------------------------------------
app.post('/ai/ask', authMiddleware, async (req, res) => {
  try {
    res.json({ ok: true, endpoint: 'ai/ask' });
  } catch (err) {
    console.error('ai/ask', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// معالج أخطاء أخير
app.use((err, _req, res, _next) => {
  console.error('unhandled', err);
  res.status(500).json({ error: 'internal_error' });
});

// ============================================================
// الإقلاع
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
