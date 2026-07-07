// db.js
// ============================================================
// Kinetic Field — طبقة قاعدة البيانات + خريطة صلاحيات RBAC
// تعكس نفس صلاحيات user_role.dart على الخادم (مصدر الحقيقة الحاسم).
//
// وظيفة الـ Auto-Migration: عند تشغيل الخادم، تُقرأ أوامر
// kinetic_field_schema.sql وتُنفَّذ لبناء الجداول إن لم تكن موجودة.
// تُنفَّذ مرة واحدة فقط طوال عمر القاعدة (حارس _schema_init).
// ============================================================
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// اتصال PostgreSQL عبر مكتبة pg — من متغيرات البيئة (لا أسرار في الكود).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'require' ? { rejectUnauthorized: false } : false,
});

// ============================================================
// الصلاحيات — مطابقة لتعداد Permission في تطبيق Flutter.
// ============================================================
const PERMISSIONS = {
  student: new Set([
    'viewPurchasedContent', 'interactWithContent', 'submitReview',
  ]),
  standard_teacher: new Set([
    'createDraftContent', 'submitForReview', 'uploadVideo',
    'manageOwnCourses', 'viewOwnBill', 'manageAccessCodes',
    'viewOwnReviews', 'viewPurchasedContent', 'interactWithContent',
  ]),
  partner_teacher: new Set([
    'createDraftContent', 'publishDirectly', 'uploadVideo',
    'manageOwnCourses', 'viewOwnBill', 'manageAccessCodes',
    'viewOwnReviews', 'viewPurchasedContent', 'interactWithContent',
  ]),
  admin: null, // null = يملك كل الصلاحيات
};

function roleCan(role, permission) {
  if (role === 'admin') return true;
  const set = PERMISSIONS[role];
  return !!set && set.has(permission);
}

// ============================================================
// initSchema — الـ Auto-Migration
//   1) يقرأ kinetic_field_schema.sql من نفس مجلد هذا الملف.
//   2) يفحص حارس _schema_init: إن طُبّق سابقاً => يتخطّى.
//   3) وإلا ينفّذ الـ SQL كاملاً داخل معاملة واحدة (كل شيء أو لا شيء).
// ============================================================
async function initSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // جدول حارس صغير: وجود صف فيه = الـ schema مُطبّق مسبقاً.
    await client.query(`
      CREATE TABLE IF NOT EXISTS _schema_init (
        applied BOOLEAN PRIMARY KEY DEFAULT TRUE,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    const { rowCount } = await client.query('SELECT 1 FROM _schema_init');

    if (rowCount > 0) {
      console.log('✔ Schema is up to date.');
    } else {
      console.log('⏳ Applying database schema...');

      // قراءة ملف الـ SQL الخارجي من نفس المجلد.
      const schemaPath = path.join(__dirname, 'kinetic_field_schema.sql');
      const sql = fs.readFileSync(schemaPath, 'utf8');

      await client.query(sql); // تنفيذ كل أوامر بناء الجداول
      await client.query('INSERT INTO _schema_init (applied) VALUES (TRUE);');
      console.log('✔ Schema applied successfully.');
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('‼ Schema init failed:', err.stack);
    process.exit(1); // إيقاف الإقلاع فوراً عند فشل القاعدة — أأمن من خادم ناقص
  } finally {
    client.release();
  }
}

module.exports = { pool, roleCan, PERMISSIONS, initSchema };
