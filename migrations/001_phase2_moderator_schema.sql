-- ============================================================
-- Phase 2 — أول مهمة: صلاحيات المشرفين (تعديلات مخطط Supabase)
-- ============================================================
-- ⚠️ لم يُنفَّذ هذا السكربت — أُعدَّ للمراجعة والتنفيذ اليدوي فقط
-- عند توفر الإنترنت. راجعه بعناية قبل التشغيل على قاعدة حية.
--
-- ملاحظة صريحة: لا أملك نص دالة ck_create_code الحالية كما هي
-- منشورة فعليًا على Supabase (ليست ملفًا بالمشروع، بل منشورة مباشرة
-- بلوحة تحكم Supabase). القسم 2 أدناه تعديل *مفاهيمي* يوضّح
-- الإضافة المطلوبة، لا استبدالًا كاملًا آمنًا للدالة — ادمجه يدويًا
-- مع تعريفك الفعلي الحالي لـck_create_code، لا تلصقه كما هو.
-- ============================================================


-- 1) عمود جديد على codes — nullable، بلا FK لجدول moderators
--    (جدول moderators نفسه خارج نطاق هذي المهمة عمدًا — قرار جلسة
--    التصميم: يُصمَّم بجلسة منفصلة عند بناء بوت الإدارة نفسه)
ALTER TABLE codes
    ADD COLUMN IF NOT EXISTS moderator_id text NULL;


-- 2) تعديل مفاهيمي مطلوب على ck_create_code الحالية —
--    ادمج هذا يدويًا مع تعريفك الفعلي:
--
--    أ) أضف معامل جديد بتوقيع الدالة:
--         p_moderator_id text DEFAULT NULL
--
--    ب) أضف العمود بجملة INSERT الحالية:
--         INSERT INTO codes (..., moderator_id)
--         VALUES (..., p_moderator_id)


-- 3) دالة RPC جديدة: ck_revoke_code
--    عملية تحديث بسيطة، بلا فحص ملكية هنا (الفحص حدث فعلًا داخل
--    CipherKeepCore.revoke_code() قبل وصول الطلب لهذا المستوى).
CREATE OR REPLACE FUNCTION ck_revoke_code(p_code text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE codes
    SET revoked = true
    WHERE code = p_code;
END;
$$;


-- 4) دالة RPC جديدة: ck_extend_code
--    نفس ملاحظة ck_revoke_code أعلاه — بلا فحص ملكية بهذا المستوى.
CREATE OR REPLACE FUNCTION ck_extend_code(p_code text, p_new_expires_at timestamptz)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE codes
    SET expires_at = p_new_expires_at
    WHERE code = p_code;
END;
$$;


-- 5) تعديل مفاهيمي مطلوب على ck_get_code الحالية —
--    تأكد أن الـSELECT يُرجع عمود moderator_id ضمن النتيجة (حتى لو
--    NULL)، حتى يقدر SupabaseCodeRepository.get() يقرأه بـPython.
--    (الكود يتعامل بمرونة مع غيابه من الصف عبر .get() احتياطًا،
--    لكن الأفضل إرجاعه صراحة لتفادي اعتماد على سلوك احتياطي دائمًا)


-- ============================================================
-- 6) جدول moderators — قرار معماري اتُّخذ أثناء تنفيذ Phase 2
--    (05_DECISIONS.md). external_id نص عام مجرَّد — لا افتراض
--    تنسيق معيّن (لا علاقة بمخطط "معرّف مشرف 3-5 أحرف" المعلَّق
--    بـ06_TODO.md #4 — ذاك قرار منفصل غير محسوم بعد).
-- ============================================================
CREATE TABLE IF NOT EXISTS moderators (
    moderator_id        text PRIMARY KEY,
    external_id          text NOT NULL UNIQUE,
    display_name         text,
    can_encrypt_server    boolean NOT NULL DEFAULT false,
    can_decrypt           boolean NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- 7) دالة RPC: ck_register_moderator
CREATE OR REPLACE FUNCTION ck_register_moderator(
    p_moderator_id text,
    p_external_id text,
    p_display_name text,
    p_can_encrypt_server boolean,
    p_can_decrypt boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO moderators (
        moderator_id, external_id, display_name,
        can_encrypt_server, can_decrypt
    )
    VALUES (
        p_moderator_id, p_external_id, p_display_name,
        p_can_encrypt_server, p_can_decrypt
    );
END;
$$;

-- 8) دالة RPC: ck_get_moderator_by_external_id
CREATE OR REPLACE FUNCTION ck_get_moderator_by_external_id(p_external_id text)
RETURNS TABLE (
    moderator_id text,
    external_id text,
    display_name text,
    can_encrypt_server boolean,
    can_decrypt boolean,
    created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT m.moderator_id, m.external_id, m.display_name,
           m.can_encrypt_server, m.can_decrypt, m.created_at
    FROM moderators m
    WHERE m.external_id = p_external_id;
END;
$$;


-- (اختياري، لو أردت سلامة مرجعية فعلية بدل عمود نصي حر)
-- ALTER TABLE codes
--     ADD CONSTRAINT fk_codes_moderator
--     FOREIGN KEY (moderator_id) REFERENCES moderators(moderator_id);
-- ⚠️ لم أُفعِّل هذا افتراضيًا: تفعيله يمنع إنشاء كود بـmoderator_id
-- لا يوجد بجدول moderators بعد — قرار يُترَك لك حسب تسلسل تشغيلك
-- الفعلي (تسجيل المشرفين أولًا أم لا).


-- ============================================================
-- ما لا يزال خارج نطاق هذا السكربت عمدًا (قرارات مؤجَّلة، لا سهو):
--   - أي منطق تفويض/مصادقة لبوت الإدارة (كود Python البوت نفسه)
--   - مخطط "معرّف مشرف مقيَّد 3-5 أحرف" (06_TODO.md #4) — منفصل تمامًا
--   - ترحيل /admin/revoke و/admin/extend القديمة من licenses.json
--     (تبقى على مسارها القديم كما هي — لا تُخلَط بهذا المسار الجديد)
-- ============================================================
