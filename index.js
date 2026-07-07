// ============================================================
// Kinetic Field — نقطة دخول الخادم (Express) — نسخة مكتفية بذاتها
// كل المسارات مُعرّفة داخل هذا الملف (بلا استيراد من routes/).
// يُطبّق initSchema (تهيئة قاعدة البيانات) قبل بدء الاستماع.
// يعمل على Railway: يستمع على process.env.PORT || 3000.
// ============================================================
const express = require('express');
const { pool, roleCan, initSchema } = require('./db');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.set('trust proxy', true); // لالتقاط req.ip الصحيح خلف بروكسي Railway

// ------------------------------------------------------------
// فحص الصحة
// ------------------------------------------------------------
app.get('/health', (_req, res) => res.json({ ok: true }));

// ------------------------------------------------------------
// /auth — تسجيل الدخول والخروج (الجلسة الواحدة النشطة)
// ------------------------------------------------------------
app.post('/auth/login', async (req, res) => {
  try {
    // TODO: تحقّق من phone/email + password_hash، ثم UPSERT على active_sessions
    // بتوكن جديد (يستبدل الجلسة السابقة تلقائياً).
    res.json({ ok: true, endpoint: 'auth/login' });
  } catch (err) {
    console.error('auth/login', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/auth/logout', async (req, res) => {
  try {
    // TODO: احذف صف active_sessions الخاص بالمستخدم.
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
