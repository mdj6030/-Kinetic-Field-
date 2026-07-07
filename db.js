// db.js
// ============================================================
// Kinetic Field — طبقة قاعدة البيانات + خريطة صلاحيات RBAC
// تعكس نفس صلاحيات user_role.dart على الخادم (مصدر الحقيقة الحاسم).
// ============================================================
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// اتصال PostgreSQL من متغيرات البيئة (لا أسرار في الكود).
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
// تهيئة قاعدة البيانات — تطبيق الـ schema أول مرة فقط.
// ============================================================
async function initSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // إنشاء جدول التتبع إذا لم يكن موجوداً
    await client.query(`
      CREATE TABLE IF NOT EXISTS _schema_init (
        applied BOOLEAN PRIMARY KEY DEFAULT TRUE,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // فحص ما إذا كان الـ schema قد طُبق سابقاً
    const { rowCount } = await client.query('SELECT 1 FROM _schema_init');

    if (rowCount > 0) {
      console.log('✔ Schema is up to date.');
    } else {
      console.log('⏳ Applying database schema...');
      const sql = fs.readFileSync(path.join(__dirname, 'kinetic_field_schema.sql'), 'utf8');
      await client.query(sql);
      await client.query('INSERT INTO _schema_init (applied) VALUES (TRUE);');
      console.log('✔ Schema applied successfully.');
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('‼ Schema init failed:', err.stack);
    process.exit(1); // إغلاق التطبيق فوراً عند فشل قاعدة البيانات
  } finally {
    client.release();
  }
}

module.exports = { pool, roleCan, PERMISSIONS, initSchema };
