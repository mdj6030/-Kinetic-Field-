// ============================================================
// Kinetic Field — نقطة دخول الخادم (Express)
// يجمع الدوال الأربع الحرجة. صالح كخادم Node أو كأساس لدوال Serverless.
// يُطبّق initSchema (تهيئة قاعدة البيانات) قبل بدء الاستماع.
// ============================================================
const express = require('express');
const { initSchema } = require('./db');
const authRoutes = require('./routes/auth');
const videoRoutes = require('./routes/video');
const codesRoutes = require('./routes/codes');
const aiRoutes = require('./routes/ai');

const app = express();
app.use(express.json({ limit: '256kb' }));
app.set('trust proxy', true); // لالتقاط req.ip الصحيح خلف بروكسي

app.get('/health', (_req, res) => res.json({ ok: true }));

app.use('/auth', authRoutes);   // /auth/login, /auth/logout
app.use('/video', videoRoutes); // /video/:lectureId/playback
app.use('/codes', codesRoutes); // /codes/redeem
app.use('/ai', aiRoutes);       // /ai/ask

// معالج أخطاء أخير.
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
    const PORT = process.env.PORT || 8080;
    app.listen(PORT, () => console.log(`🚀 Kinetic Field API on ${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

module.exports = app;
