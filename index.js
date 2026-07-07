// ============================================================
// Kinetic Field — نقطة دخول الخادم (Express) — نسخة مكتفية بذاتها
// كل المسارات مُعرّفة داخل هذا الملف (بلا استيراد من routes/).
// يُطبّق initSchema (تهيئة قاعدة البيانات) قبل بدء الاستماع.
// يعمل على Railway: يستمع على process.env.PORT || 3000.
// ============================================================
const express = require('express');
const bcrypt = require('bcryptjs'); // لمقارنة password_hash بأمان
const { pool, roleCan, initSchema } = require('./db');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.set('trust proxy', true); // لالتقاط req.ip الصحيح خلف بروكسي Railway

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
//   1) البحث عن المستخدم بالبريد أو الهاتف
//   2) التحقق من password_hash عبر bcrypt
//   3) UPSERT على active_sessions بتوكن جديد (يستبدل أي جلسة سابقة)
// ------------------------------------------------------------
app.post('/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    // identifier = البريد أو رقم الهاتف (حقل دخول واحد مرن)

    if (!identifier || !password) {
      return res.status(400).json({ error: 'missing_credentials' });
    }

    // 1) البحث عن المستخدم بالبريد (email) أو الهاتف (phone).
    //    email من نوع CITEXT فالمقارنة غير حساسة لحالة الأحرف تلقائياً.
    const userResult = await pool.query(
      `SELECT id, role, full_name, password_hash, is_active
         FROM users
        WHERE email = $1 OR phone = $1
        LIMIT 1`,
      [identifier]
    );

    if (userResult.rowCount === 0) {
      // رسالة موحّدة لعدم كشف إن كان الحساب موجوداً أم لا.
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'account_disabled' });
    }

    // 2) التحقق من كلمة المرور مقابل password_hash المخزّن.
    const passwordOk = await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // 3) إنشاء/استبدال الجلسة: UPSERT على user_id (المفتاح الأساسي).
    //    session_token يُولَّد عبر uuid_generate_v4() داخل القاعدة.
    //    أي جلسة قديمة لنفس user_id تُستبدل فوراً => جلسة واحدة نشطة.
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

    const sessionToken = sessionResult.rows[0].session_token;

    return res.json({
      ok: true,
      session_token: sessionToken, // يُرسله العميل في كل طلب لاحق
      user: {
        id: user.id,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('auth/login', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/auth/logout', async (req, res) => {
  try {
    // TODO: احذف صف active_sessions الخاص بالمستخدم (بعد التحقق من التوكن).
    res.json({ ok: true, endpoint: 'auth/logout' });
  } catch (err) {
    console.error('auth/logout', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /video — رابط تشغيل المحاضرة (مع العلامة المائية والتحقق من الشراء)
// ------------------------------------------------------------
app.get('/video/:lectureId/playback', async (req, res) => {
  try {
    const { lectureId } = req.params;
    // TODO: تحقّق من ملكية الطالب للكورس، ثم أصدر رابطاً موقّعاً + watermark token.
    res.json({ ok: true, endpoint: 'video/playback', lectureId });
  } catch (err) {
    console.error('video/playback', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /codes — تفعيل كود الوصول
// ------------------------------------------------------------
app.post('/codes/redeem', async (req, res) => {
  try {
    // TODO: تحقّق من حالة الكود (active)، فعّله (used)، وأنشئ enrollment للطالب.
    res.json({ ok: true, endpoint: 'codes/redeem' });
  } catch (err) {
    console.error('codes/redeem', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// ------------------------------------------------------------
// /ai — سؤال الذكاء الاصطناعي (مع كاش لتصفير الاستهلاك)
// ------------------------------------------------------------
app.post('/ai/ask', async (req, res) => {
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
    await initSchema(); // تهيئة قاعدة البيانات أولاً
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 Kinetic Field API on ${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

module.exports = app;
