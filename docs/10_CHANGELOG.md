# 10 — سجل التغييرات (Changelog)

*(الأقسام السابقة كما هي بلا تعديل — هذا القسم إضافة بنهاية الملف)*

## 🟢 إغلاق Phase 1 رسميًا

- كل بنود `PHASE1_CHECKLIST.md` (22/22) ✅ مكتمل، مؤكَّدة بإثبات حي فعلي
- البند #17 (بوت التشفير) أُثبت حيًا: دورة كاملة عبر بوت تيليجرام حقيقي — إنشاء كود `EFU-YNRV` → تشفير → تفعيل ناجح
- البند #19 (سيناريو فشل الاتصال) أُثبت حيًا، مع اكتشاف وإصلاح فعليين أثناء الاختبار:
  - تسرّب استثناء خام (`ConnectionError`/`SupabaseRequestError`) بلا معالجة عند فشل اتصال فعلي بـSupabase أثناء الطلب (لا الإقلاع فقط)
  - ابتلاع صامت لخطأ حقيقي بـ`admin_pause_all` بسبب `except RuntimeError` عام يلتقط `SupabaseRequestError` (وريثة `RuntimeError`) خطأً

## مراجعة أمنية شاملة (Security & Architecture Review) — قبل الإغلاق النهائي

نُفِّذت مراجعتان (Red Team + هندسية) اكتشفتا 15+ نقطة، عولجت منها:

- **R1**: فصل تحقق صلاحية الكود عن حجز سلوت الجهاز — الحجز أصبح مشروطًا بنجاح فك التشفير فعليًا (`check_code_validity`, `register_device`, `CodeValidityResult`, `DeviceRegistrationResult` — كلها إضافات جديدة، `verify_code` الأصلية بلا تغيير سلوكي)
- **C1**: مسار إداري منفصل (`admin_force_revoke`, `admin_pause_all`, `CodeQueryRepository`) يوصّل `/admin/revoke`+`/admin/pause_all` بـSupabase فعليًا، بلا فحص ملكية (صلاحية إدارية أعلى من أي مشرف فردي)
- **H1**: توحيد رد `/verify` لكل حالات فشل صلاحية الكود (`not_found`/`revoked`/`expired`) — رد واحد، معاملة Rate Limit موحَّدة (Fail Closed)
- **H2**: بنية تدوير يدوي لـ`ADMIN_TOKEN` (`ADMIN_TOKENS_ROTATION`)، معطَّلة افتراضيًا
- **H3**: واجهة `FailureTrackerRepository` + `InMemoryFailureTracker` + `SupabaseFailureTrackerRepository` (stub موثَّق لـPhase 2)
- **H4**: سياسة كلمة مرور (12 حرفًا + تعقيد) عند الإنشاء فقط، بلا كسر توافق فك تشفير ملفات قديمة
- **H5**: حذف الملف المصدري بعد نجاح التشفير ببوت التشفير
- **H6**: إزالة تضمين كود التفعيل بنص واضح من اللانشر
- **L1**: تسجيل فشل الإشعار بدل ابتلاعه صامتًا
- **L2**: فرض HTTPS على `LICENSE_SERVER_URL` ببوت التشفير
- **`RepositoryNotConfigured`**: استثناء جديد لا يرث من `RuntimeError` عمدًا — يمنع تصادمًا مستقبليًا مع `SupabaseRequestError`

**Compatibility Fix حاسم**: `SupabaseCodeRepository.create()` لا ترسل `p_moderator_id` بالـpayload إطلاقًا لو `None` — ضرورية للتوافق مع توقيع `ck_create_code` المنشور حيًا (بلا هذا المعامل)، مثبَتة حيًا عبر رد فعلي ناجح (`{"ok": true, "code": "HJM-NK66", ...}`)

**المجموع الآلي النهائي: 71/71 اختبار ناجح**، مؤكَّد عبر `pytest` على بيئة تشغيل حية (Termux Android، Python 3.14.6) — تجاوز حتى معيار التشغيل المحلي المعتاد.

## بداية Phase 2 (بعد هذا الإغلاق مباشرة)

أول مهمة: ترحيل `/admin/list`, `/admin/revoke`, `/admin/pause_all`, `/admin/extend` بالكامل لـSupabase، حذف `licenses.json`، ثم نظام صلاحيات المشرفين (Owner → Moderators → Customers).
