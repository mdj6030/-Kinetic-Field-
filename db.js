// db.js
// ============================================================
// Kinetic Field — طبقة قاعدة البيانات + خريطة صلاحيات RBAC
// تعكس نفس صلاحيات user_role.dart على الخادم (مصدر الحقيقة الحاسم).
// نسخة مكتفية بذاتها: الـ schema مضمّن كنص داخل هذا الملف،
// فلا حاجة لقراءة kinetic_field_schema.sql خارجياً على Railway.
// ============================================================
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
// مخطط قاعدة البيانات (Schema) مضمّن كنص.
// ملاحظة: مكتوب داخل String.raw لتفادي أي تأويل لرموز مثل \ داخل SQL.
// ============================================================
const SCHEMA_SQL = String.raw`
-- =====================================================================
--  KINETIC FIELD  —  DATABASE SCHEMA (PostgreSQL)
--  منصة تعليمية سيادية | Serverless-friendly relational schema
--  Version: 1.0  |  Generated: 2026-07-06
--
--  يغطي:
--   - RBAC بأربع رتب (طالب / مدرس قياسي / شريك استراتيجي / مدير)
--   - الجلسة الواحدة النشطة (Single Active Session)
--   - أكواد الوصول بكل خياراتها الفرعية
--   - الفوترة الشهرية (حصة المنصة 12%)
--   - الشجرة الأكاديمية المتسلسلة + الباقات (Bundles)
--   - المحاضرات/الأقسام/المرفقات/الكويز
--   - التقييمات + وضع الشبح (Soft-Delete يدوي للمدير)
--   - نسبة إكمال المشاهدة + استئناف التشغيل
--   - سجل تدقيق غير قابل للتعديل + موافقات تعاقدية موثّقة
--   - كاش الذكاء الاصطناعي (تصفير الاستهلاك)
-- =====================================================================

-- ---------- امتدادات مساعدة ----------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";      -- بريد/معرّفات غير حساسة لحالة الأحرف

-- ---------- أنواع مُعرّفة (ENUMs) ----------
CREATE TYPE user_role AS ENUM (
  'student',            -- الطالب
  'standard_teacher',   -- المدرس القياسي (Double-Draft)
  'partner_teacher',    -- الشريك الاستراتيجي (نشر مباشر)
  'admin'               -- المدير / CEO
);

CREATE TYPE content_status AS ENUM (
  'draft',              -- مسودة
  'pending_review',     -- بانتظار المراجعة (الدفعة الثانية من Double-Draft)
  'published',          -- منشور
  'hidden',             -- مخفي (مثلاً فيديو قيد المعالجة)
  'suspended'           -- معلّق (إخلال تعاقدي)
);

CREATE TYPE university_type AS ENUM (
  'ministerial',        -- وزاري
  'non_ministerial'     -- غير وزاري
);

CREATE TYPE access_code_status AS ENUM (
  'active',             -- نشط غير مستخدم
  'used',               -- مُستخدم
  'shared',             -- مُولّد ضمن مشاركة/توزيع
  'deleted'             -- محذوف (soft-delete)
);

CREATE TYPE purchase_source AS ENUM (
  'direct',             -- شراء مباشر داخل التطبيق
  'access_code'         -- تفعيل عبر كود وصول
);

CREATE TYPE review_visibility AS ENUM (
  'visible',            -- ظاهر للعامة ومحسوب في المعدل
  'shadow_hidden'       -- وضع الشبح: مخفي عن العامة، مستثنى من المعدل، مرئي لصاحبه
);

CREATE TYPE settlement_status AS ENUM (
  'pending',            -- مستحق غير مسدَّد
  'settled',            -- مسدَّد
  'in_default'          -- متعثّر (تجاوز مهلة التسوية)
);

-- =====================================================================
--  1) المستخدمون والصلاحيات (RBAC)
-- =====================================================================
CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  role              user_role NOT NULL DEFAULT 'student',
  full_name         TEXT NOT NULL,
  phone             TEXT UNIQUE,                 -- رقم الهاتف (لا يُعرض في العلامة المائية)
  email             CITEXT UNIQUE,
  password_hash     TEXT NOT NULL,
  avatar_url        TEXT,
  bio               TEXT,                         -- نبذة (About) لصفحة المحاضر
  headline          TEXT,                         -- الصفة تحت الاسم (مثال: خريج كلية الصيدلة)
  telegram_url      TEXT,
  instagram_url     TEXT,

  -- استثناء المدير من FLAG_SECURE يُربط بالجهاز/الجلسة لا بالحساب فقط (أمان)
  screen_capture_exempt BOOLEAN NOT NULL DEFAULT FALSE,

  -- بيانات تعريف المحاضر (تتبّع قانوني) — مطلوبة للتسجيل بصفة محاضر فقط.
  -- تُخزَّن مشفّرة على مستوى التطبيق/القرص، ولا تُعرض إلا للمدير عند الحاجة.
  legal_full_name   TEXT,     -- الاسم الثلاثي الكامل
  legal_phone       TEXT,     -- رقم الهاتف (تعريفي — منفصل عن phone الدخول)
  legal_address     TEXT,     -- عنوان السكن التفصيلي
  identity_verified BOOLEAN NOT NULL DEFAULT FALSE,
  identity_submitted_at TIMESTAMPTZ,

  is_active         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_role ON users(role);
-- فرض على مستوى التطبيق: لا يُرقّى مستخدم إلى standard_teacher/partner_teacher
-- ولا يُنشر أي محتوى قبل تعبئة legal_full_name + legal_phone + legal_address.
-- (يُفضَّل فرضه أيضاً بـ trigger عند تغيير الدور إلى رتبة محاضر.)

-- تفعيل استثناء التصوير فقط لجهاز/جلسة مصرّح بها (لا يكفي كون الحساب admin)
CREATE TABLE screen_capture_grants (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_label  TEXT,                             -- وصف الجهاز المصرّح (شاشة التدريب)
  granted_by    UUID NOT NULL REFERENCES users(id),
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at    TIMESTAMPTZ
);

-- =====================================================================
--  2) الجلسة الواحدة النشطة (Single Active Session)
--     كل دخول ناجح يستبدل الجلسة السابقة؛ الجهاز القديم يُرفض عند أول طلب.
-- =====================================================================
CREATE TABLE active_sessions (
  user_id           UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  session_token     UUID NOT NULL UNIQUE,         -- التوكن الوحيد الصالح للحساب
  device_fingerprint TEXT,                        -- بصمة الجهاز (تشخيصية فقط)
  device_label      TEXT,
  ip_address        INET,
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- المنطق: عند دخول جديد → UPSERT على user_id بتوكن جديد.
-- أي طلب يحمل توكناً لا يساوي session_token الحالي => 401 وطرد فوري.

-- =====================================================================
--  3) الشجرة الأكاديمية المتسلسلة (Taxonomy)
--     مؤسسة > تخصص/كلية > مرحلة > نوع المادة (وزاري/غير وزاري) > كورس/موسم
-- =====================================================================
CREATE TABLE institutions (          -- نوع المؤسسة التعليمية
  id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name_ar   TEXT NOT NULL,
  name_en   TEXT,
  sort_order INT NOT NULL DEFAULT 0
);

CREATE TABLE specialties (           -- التخصص / الكلية
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  institution_id UUID REFERENCES institutions(id) ON DELETE CASCADE,
  name_ar        TEXT NOT NULL,      -- صيدلة، طب عام، طب أسنان، تقنيات التخدير...
  name_en        TEXT,
  sort_order     INT NOT NULL DEFAULT 0
);

CREATE TABLE stages (                -- المرحلة الدراسية
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name_ar    TEXT NOT NULL,          -- جميع المراحل، مرحلة اولى ... خامسة
  name_en    TEXT,
  rank       INT NOT NULL,           -- 0 = جميع المراحل، ثم 1..n
  UNIQUE(rank)
);

-- المواضيع (Topics) لشريط الاستكشاف — تشمل "Free courses" كعلامة
CREATE TABLE topics (
  id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name_ar   TEXT,
  name_en   TEXT NOT NULL,           -- Pharmacology, Anatomy, Free courses...
  is_system BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE لـ "Free courses"
  sort_order INT NOT NULL DEFAULT 0
);

-- =====================================================================
--  4) الباقات والكورسات (Bundles & Courses)
-- =====================================================================
CREATE TABLE bundles (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id     UUID NOT NULL REFERENCES users(id),
  title        TEXT NOT NULL,
  description  TEXT,
  cover_url    TEXT,
  status       content_status NOT NULL DEFAULT 'draft',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE courses (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id        UUID NOT NULL REFERENCES users(id),      -- المحاضر المالك
  bundle_id       UUID REFERENCES bundles(id) ON DELETE SET NULL,
  title           TEXT NOT NULL,
  description      TEXT,
  cover_url       TEXT,
  telegram_url    TEXT,

  -- إحداثيات الشجرة الأكاديمية
  specialty_id    UUID REFERENCES specialties(id),
  stage_id        UUID REFERENCES stages(id),
  university_type university_type,                          -- وزاري / غير وزاري
  university_name TEXT,                                     -- جامعة بغداد، جميع الجامعات...

  price_iqd       INTEGER NOT NULL DEFAULT 0 CHECK (price_iqd >= 0),
  is_free         BOOLEAN NOT NULL DEFAULT FALSE,           -- كورس مجاني بالكامل

  -- حالة النشر:
  --   partner_teacher => published مباشرة
  --   standard_teacher => draft → pending_review → published
  status          content_status NOT NULL DEFAULT 'draft',

  -- عدادات مشتقّة (تُحدَّث أو تُحسب عبر VIEW)
  student_count   INTEGER NOT NULL DEFAULT 0,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_courses_owner   ON courses(owner_id);
CREATE INDEX idx_courses_filter  ON courses(specialty_id, stage_id, university_type);
CREATE INDEX idx_courses_status  ON courses(status);

-- ربط الكورسات بالمواضيع (Topics) — علاقة كثير-لكثير
CREATE TABLE course_topics (
  course_id UUID REFERENCES courses(id) ON DELETE CASCADE,
  topic_id  UUID REFERENCES topics(id)  ON DELETE CASCADE,
  PRIMARY KEY (course_id, topic_id)
);

-- =====================================================================
--  5) الأقسام والمحاضرات والمرفقات (Sections / Lectures / Attachments)
-- =====================================================================
CREATE TABLE course_sections (       -- الأقسام (Introduction / Chapter N)
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  course_id   UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  sort_order  INT NOT NULL DEFAULT 0                          -- لإعادة الترتيب
);
CREATE INDEX idx_sections_course ON course_sections(course_id, sort_order);

CREATE TABLE lectures (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  section_id    UUID NOT NULL REFERENCES course_sections(id) ON DELETE CASCADE,
  course_id     UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE, -- تكرار مقصود للاستعلام السريع
  title         TEXT NOT NULL,
  description   TEXT,

  -- الفيديو عبر BunnyCDN حصراً (لا روابط خارجية / لا Embeds)
  bunny_video_id   TEXT,                                     -- معرّف الفيديو في BunnyCDN Stream
  duration_seconds INTEGER,                                  -- المدة (تُقرأ بعد المعالجة)
  is_processed     BOOLEAN NOT NULL DEFAULT FALSE,           -- مخفية حتى تكتمل المعالجة

  is_free_preview  BOOLEAN NOT NULL DEFAULT FALSE,           -- وسم "مجاني" لكل محاضرة
  sort_order       INT NOT NULL DEFAULT 0,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_lectures_section ON lectures(section_id, sort_order);
CREATE INDEX idx_lectures_course  ON lectures(course_id);

-- المرفقات (PDF / Infographics) على مستوى المحاضرة أو الكورس
CREATE TABLE attachments (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  course_id   UUID REFERENCES courses(id)  ON DELETE CASCADE,
  lecture_id  UUID REFERENCES lectures(id) ON DELETE CASCADE,
  file_url    TEXT NOT NULL,
  file_name   TEXT NOT NULL,
  file_type   TEXT,                                          -- pdf / image
  is_downloadable BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (course_id IS NOT NULL OR lecture_id IS NOT NULL)   -- يجب ربطها بأحدهما
);

-- =====================================================================
--  6) الكويز (Quizzes)
-- =====================================================================
CREATE TABLE quizzes (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  course_id   UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  section_id  UUID REFERENCES course_sections(id) ON DELETE SET NULL,
  title       TEXT NOT NULL,
  sort_order  INT NOT NULL DEFAULT 0
);

CREATE TABLE quiz_questions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  quiz_id     UUID NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  prompt      TEXT NOT NULL,
  sort_order  INT NOT NULL DEFAULT 0
);

CREATE TABLE quiz_options (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  question_id UUID NOT NULL REFERENCES quiz_questions(id) ON DELETE CASCADE,
  option_text TEXT NOT NULL,
  is_correct  BOOLEAN NOT NULL DEFAULT FALSE,
  sort_order  INT NOT NULL DEFAULT 0
);

-- =====================================================================
--  7) أكواد الوصول (Access Codes) — بكل خياراتها الفرعية من اللقطة
-- =====================================================================
CREATE TABLE access_codes (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code          TEXT NOT NULL UNIQUE,             -- BAU7-C5KY-V97A
  course_id     UUID REFERENCES courses(id) ON DELETE CASCADE,
  bundle_id     UUID REFERENCES bundles(id) ON DELETE CASCADE,
  value_iqd     INTEGER NOT NULL DEFAULT 0,       -- القيمة المعروضة بالدينار
  status        access_code_status NOT NULL DEFAULT 'active',

  is_shared     BOOLEAN NOT NULL DEFAULT FALSE,   -- وسم "Shared"
  created_by    UUID NOT NULL REFERENCES users(id),
  used_by       UUID REFERENCES users(id),        -- من فعّله
  used_at       TIMESTAMPTZ,                       -- تاريخ الاستخدام (للفرز/الإخفاء)
  deleted_at    TIMESTAMPTZ,                       -- soft-delete (إخفاء الأكواد المحذوفة)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (course_id IS NOT NULL OR bundle_id IS NOT NULL)
);
CREATE INDEX idx_codes_course ON access_codes(course_id);
CREATE INDEX idx_codes_status ON access_codes(status);
CREATE INDEX idx_codes_used_at ON access_codes(used_at);
-- خيارات الشاشة تُنفَّذ كفلاتر استعلام:
--   Hide used (older than 2 days): status='used' AND used_at < now()-'2 days'
--   Order by date (only used):     WHERE status='used' ORDER BY used_at DESC
--   Hide deleted:                  WHERE deleted_at IS NULL
--   Enable other sharing options:  عبر جدول code_share_links أدناه (placeholder جاهز للتوسعة)

CREATE TABLE code_share_links (      -- "Enable other sharing options" — قابل للتوسعة
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code_id     UUID NOT NULL REFERENCES access_codes(id) ON DELETE CASCADE,
  share_token TEXT NOT NULL UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
--  8) المشتريات / التسجيل (Enrollments & Purchases)
--     "من لا يدفع لا يحصل على شيء" — لا وصول بلا صف هنا
-- =====================================================================
CREATE TABLE enrollments (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  student_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  course_id     UUID REFERENCES courses(id) ON DELETE CASCADE,
  bundle_id     UUID REFERENCES bundles(id) ON DELETE CASCADE,
  source        purchase_source NOT NULL,
  access_code_id UUID REFERENCES access_codes(id),
  amount_paid_iqd INTEGER NOT NULL DEFAULT 0,
  enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(student_id, course_id),                   -- لا تكرار للكورس نفسه
  CHECK (course_id IS NOT NULL OR bundle_id IS NOT NULL)
);
CREATE INDEX idx_enroll_student ON enrollments(student_id);
CREATE INDEX idx_enroll_course  ON enrollments(course_id);

-- =====================================================================
--  9) الفوترة (Bill) — للمحاضر حصراً | حصة المنصة 12%
--     يُعرض: مبيعات هذا الشهر + الإجمالي التاريخي (رقم فقط)
--     الأرباح تُحسب من الشهر الجاري فقط.
-- =====================================================================
CREATE TABLE sales (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  course_id     UUID NOT NULL REFERENCES courses(id),
  teacher_id    UUID NOT NULL REFERENCES users(id),
  student_id    UUID NOT NULL REFERENCES users(id),
  enrollment_id UUID REFERENCES enrollments(id),
  gross_iqd     INTEGER NOT NULL,                  -- سعر البيع
  platform_cut_iqd INTEGER NOT NULL,               -- 12% (يُحسب وقت البيع ويُجمَّد)
  teacher_net_iqd  INTEGER NOT NULL,               -- 88%
  sold_at       TIMESTAMPTZ NOT NULL DEFAULT now() -- الطابع الزمني لحساب "الشهري"
);
CREATE INDEX idx_sales_teacher_time ON sales(teacher_id, sold_at);
CREATE INDEX idx_sales_course_time  ON sales(course_id, sold_at);

-- نسبة المنصة قابلة للتعديل مركزياً (افتراضي 12%)
CREATE TABLE platform_settings (
  id                   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),  -- صف واحد فقط
  platform_cut_percent NUMERIC(5,2) NOT NULL DEFAULT 12.00,
  settlement_grace_days INT NOT NULL DEFAULT 30,   -- مهلة التسوية قبل التعثّر
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO platform_settings (id) VALUES (TRUE) ON CONFLICT DO NOTHING;

-- VIEW: ملخص فوترة المحاضر — الشهر الجاري + الإجمالي التاريخي
CREATE OR REPLACE VIEW teacher_bill_view AS
SELECT
  c.id                 AS course_id,
  c.owner_id           AS teacher_id,
  c.title              AS course_title,
  -- هذا الشهر
  COUNT(*) FILTER (WHERE date_trunc('month', s.sold_at) = date_trunc('month', now()))          AS sales_count_this_month,
  COALESCE(SUM(s.gross_iqd)      FILTER (WHERE date_trunc('month', s.sold_at) = date_trunc('month', now())),0) AS gross_this_month,
  COALESCE(SUM(s.teacher_net_iqd)FILTER (WHERE date_trunc('month', s.sold_at) = date_trunc('month', now())),0) AS net_profit_this_month,
  -- الإجمالي التاريخي: عدد ومبلغ فقط، بلا حساب ربح (كي لا يُستكبر الرقم)
  COUNT(*)                                                                                       AS sales_count_total,
  COALESCE(SUM(s.gross_iqd),0)                                                                   AS gross_total
FROM courses c
LEFT JOIN sales s ON s.course_id = c.id
GROUP BY c.id, c.owner_id, c.title;
-- الوصول لهذا الـ VIEW يجب تقييده في طبقة التطبيق: المحاضر يرى صفوفه فقط.

-- =====================================================================
--  10) التسويات والتعثّر التعاقدي (Settlements & Default)
--      أساس البند التعاقدي: تعثّر التسديد ⇒ تعليق الوصول + حق التصرف المحصور بالضرر
-- =====================================================================
CREATE TABLE settlements (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  teacher_id      UUID NOT NULL REFERENCES users(id),
  period_month    DATE NOT NULL,                  -- الشهر المعني (أول يوم)
  total_net_iqd   INTEGER NOT NULL DEFAULT 0,     -- المستحق للمحاضر
  status          settlement_status NOT NULL DEFAULT 'pending',
  due_date        DATE NOT NULL,
  settled_at      TIMESTAMPTZ,
  in_default_since TIMESTAMPTZ,                    -- بدء التعثّر (بعد المهلة)
  UNIQUE(teacher_id, period_month)
);

-- سجل إجراءات التعليق/التصرف عند الإخلال (شفافية قانونية)
CREATE TABLE contract_enforcement_actions (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  teacher_id    UUID NOT NULL REFERENCES users(id),
  settlement_id UUID REFERENCES settlements(id),
  action        TEXT NOT NULL,                     -- 'access_suspended' / 'content_retained'
  reason        TEXT NOT NULL,
  acted_by      UUID NOT NULL REFERENCES users(id),
  acted_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
--  11) الموافقات التعاقدية الموثّقة (لتقوية البنود ضد الطعن)
-- =====================================================================
CREATE TABLE contract_agreements (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_key  TEXT NOT NULL,                     -- 'teacher_terms_v1' ...
  document_version TEXT NOT NULL,
  accepted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_address    INET,
  device_fingerprint TEXT,
  UNIQUE(user_id, document_key, document_version)
);

-- =====================================================================
--  12) التقييمات + وضع الشبح (Reviews & Shadow Ban)
--      إخفاء يدوي حصري للمدير — لا فلاتر ذكاء اصطناعي (القرار بشري 100%)
-- =====================================================================
CREATE TABLE reviews (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  course_id     UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  student_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rating        SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment       TEXT,
  visibility    review_visibility NOT NULL DEFAULT 'visible',
  -- حقول وضع الشبح:
  shadow_hidden_by UUID REFERENCES users(id),      -- يجب أن يكون admin (يُفرض بالتطبيق)
  shadow_hidden_at TIMESTAMPTZ,
  shadow_reason    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(course_id, student_id)                    -- تقييم واحد لكل طالب لكل كورس
);
CREATE INDEX idx_reviews_course ON reviews(course_id);

-- المعدل المعروض للعامة يستثني وضع الشبح
CREATE OR REPLACE VIEW course_rating_view AS
SELECT course_id,
       ROUND(AVG(rating) FILTER (WHERE visibility='visible'), 1) AS avg_rating,
       COUNT(*)          FILTER (WHERE visibility='visible')     AS ratings_count
FROM reviews
GROUP BY course_id;
-- ملاحظة: التقييم المُخفى يبقى مرئياً لصاحبه (student_id) عبر استعلام خاص في التطبيق.

-- =====================================================================
--  13) تقدّم المشاهدة + استئناف التشغيل (Progress & Resume)
--      الطابع الزمني يُحفظ محلياً أيضاً؛ هنا نسخة الخادم للتقارير.
-- =====================================================================
CREATE TABLE watch_progress (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  student_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lecture_id         UUID NOT NULL REFERENCES lectures(id) ON DELETE CASCADE,
  last_position_sec  INTEGER NOT NULL DEFAULT 0,   -- استئناف التشغيل
  completion_percent SMALLINT NOT NULL DEFAULT 0 CHECK (completion_percent BETWEEN 0 AND 100),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(student_id, lecture_id)
);
CREATE INDEX idx_progress_student ON watch_progress(student_id);

-- =====================================================================
--  14) كاش الذكاء الاصطناعي (تصفير الاستهلاك)
--      يُخزَّن حسب بصمة السؤال؛ يُقدَّم للطلاب الآخرين دون استدعاء API.
--      طبقة تجريد للمزوّد (provider) لتبديله بسطر واحد لاحقاً إن لزم.
-- =====================================================================
CREATE TABLE ai_cache (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scope_lecture_id UUID REFERENCES lectures(id) ON DELETE CASCADE,
  prompt_hash   TEXT NOT NULL,                     -- SHA-256 لنص السؤال المُطبَّع
  prompt_text   TEXT NOT NULL,
  response_text TEXT NOT NULL,
  provider      TEXT NOT NULL DEFAULT 'gemini-free',
  hit_count     INTEGER NOT NULL DEFAULT 0,        -- كم مرة خدم الكاش الطلاب
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(scope_lecture_id, prompt_hash)
);
CREATE INDEX idx_ai_cache_hash ON ai_cache(prompt_hash);

-- =====================================================================
--  15) العلامة المائية الديناميكية (Watermark) — User ID لا رقم الهاتف
--      لا حاجة لجدول للعرض (يُولّد وقت التشغيل)، لكن نسجّل معرّف العرض للتتبّع.
-- =====================================================================
CREATE TABLE watermark_tokens (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  opaque_id     TEXT NOT NULL,                     -- معرّف مبهم يُعرض على الفيديو
  lecture_id    UUID REFERENCES lectures(id),
  issued_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =====================================================================
--  16) سجل التدقيق غير القابل للتعديل (Audit Log)
--      يوثّق كل soft-delete/تعليق/إجراء إداري حسّاس.
-- =====================================================================
CREATE TABLE audit_log (
  id            BIGSERIAL PRIMARY KEY,
  actor_id      UUID REFERENCES users(id),
  action        TEXT NOT NULL,
  entity_type   TEXT NOT NULL,
  entity_id     UUID,
  metadata      JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- يُمنع UPDATE/DELETE على هذا الجدول عبر صلاحيات قاعدة البيانات (append-only).
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);

-- =====================================================================
--  نهاية المخطط
-- =====================================================================
`;

// ============================================================
// تهيئة قاعدة البيانات — تطبيق الـ schema المضمّن أول مرة فقط.
// تُنفّذ SCHEMA_SQL مباشرة عبر pool.query() بدل fs.readFileSync.
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
      await client.query(SCHEMA_SQL); // تنفيذ المتغير النصي مباشرة
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

module.exports = { pool, roleCan, PERMISSIONS, initSchema, SCHEMA_SQL };
