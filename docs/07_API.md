# 07 — العقود (API / Contracts)

## ما يُعتبَر "تعديل عقد"

أي إضافة/حذف/تغيير نوع حقل، أو تغيير شكل مدخل/مخرج أي نقطة HTTP. يحتاج موافقة مسبقة دائمًا.

---

## عقود Core (بايثون)

### `VerifyResult` — **مُغلَق نهائيًا، صفر إضافة حتى بعد Phase 2**
```python
ok: bool
reason: Optional[str]        # not_found | revoked | expired | device_limit_reached
key_material: Optional[bytes]
is_new_device: bool = False
label: Optional[str] = None
```
**ملاحظة معتمَدة:** بدل توسيع هذا العقد لسياقات جديدة (كالحاجة لتحقق بلا حجز)، أُنشئت أنواع جديدة مستقلة (`CodeValidityResult` أدناه) — هذا هو النمط المعتمَد الآن لأي حاجة مشابهة مستقبلية.

### `CodeValidityResult` — جديد (إصلاح R1)
```python
ok: bool
reason: Optional[str]
key_material: Optional[bytes]
label: Optional[str] = None
```
نتيجة `CipherKeepCore.check_code_validity()`. نوع منفصل تمامًا عن `VerifyResult` (لا حقل `is_new_device` — لا معنى له، لا حجز حدث بعد).

### `DeviceRegistrationResult` — جديد (إصلاح R1)
```python
ok: bool
reason: Optional[str] = None      # 'not_found' | 'revoked' | 'expired' لو ok=False
claim_status: Optional[DeviceClaimStatus] = None   # لو ok=True
```
نتيجة `CipherKeepCore.register_device()`.

### `DecryptedVerifyResult` (داخل `ServerModeService`) — بلا تغيير
```python
ok: bool
reason: Optional[str]
filename: Optional[str]
source_bytes: Optional[bytes]
is_new_device: bool
label: Optional[str] = None
```

### `DeviceClaimStatus` (Enum) — بلا تغيير
```python
REGISTERED | ALREADY_REGISTERED | LIMIT_REACHED
```

### `RevokeResult` / `ExtendResult` — بلا تغيير
```python
# RevokeResult
ok: bool
reason: Optional[str] = None   # 'not_found' | 'not_owner'

# ExtendResult
ok: bool
reason: Optional[str] = None
new_expires_at: Optional[datetime] = None
```
**ملاحظة:** `admin_force_revoke()` (C1) تُرجع نفس `RevokeResult` — بلا عقد جديد، فقط منطق تجاوز ملكية مختلف داخليًا.

### `Moderator` — بلا تغيير
```python
moderator_id: str
external_id: str
display_name: Optional[str]
can_encrypt_server: bool
can_decrypt: bool
created_at: datetime
```

### `RepositoryNotConfigured(Exception)` — جديد (إصلاح #19)
استثناء عام (**لا يرث من `RuntimeError`** عمدًا)، يُرفَع من `register_moderator()` و`admin_pause_all()` عند غياب المستودع الاختياري المطلوب.

---

### الواجهات المجرَّدة
```python
CodeRepository.create(code, key_material, label, max_devices, trial, expires_at, moderator_id=None) -> None
CodeRepository.get(code) -> Optional[LicenseCode]
CodeRepository.revoke(code) -> None
CodeRepository.extend(code, new_expires_at) -> None

DeviceRepository.claim_device_slot(code, device_fingerprint, now) -> DeviceClaimStatus

ModeratorRepository.create(moderator_id, external_id, display_name, can_encrypt_server, can_decrypt) -> None
ModeratorRepository.get_by_external_id(external_id) -> Optional[Moderator]

# جديدة (إصلاح C1)
CodeQueryRepository.list_all_codes() -> List[str]
```

### دوال `CipherKeepCore` — كاملة، محدَّثة

```python
CipherKeepCore.__init__(codes, devices, moderators=None, admin_codes=None)

# الأصلية — بلا تغيير بالسلوك
CipherKeepCore.create_code(code, key_material, label=None, max_devices=1, trial=False, expires_at=None, moderator_id=None) -> None
CipherKeepCore.verify_code(code, device_fingerprint, now=None) -> VerifyResult
CipherKeepCore.revoke_code(code, moderator_id) -> RevokeResult
CipherKeepCore.extend_code(code, moderator_id, new_expires_at) -> ExtendResult
CipherKeepCore.register_moderator(moderator_id, external_id, display_name=None, can_encrypt_server=False, can_decrypt=False) -> None
CipherKeepCore.resolve_moderator(external_id) -> Optional[Moderator]

# جديدة (إصلاح R1)
CipherKeepCore.check_code_validity(code, now=None) -> CodeValidityResult
CipherKeepCore.register_device(code, device_fingerprint, now=None) -> DeviceRegistrationResult

# جديدة (إصلاح C1)
CipherKeepCore.admin_force_revoke(code) -> RevokeResult
CipherKeepCore.admin_pause_all() -> int   # يرفع RepositoryNotConfigured لو بلا admin_codes
```

---

## نقاط HTTP

### `POST /verify` — مُرحَّلة لـSupabase بالكامل
**مدخل:** `{code, device_id, ciphertext_b64}`
**مخرج نجاح (200):** `{ok: true, name, source_b64}`

**مخرج فشل — محدَّث (إصلاح H1 + #19):**
| reason | HTTP | ملاحظة |
|---|---|---|
| `rate_limited` | 429 | فحص IP، Adapter بحت |
| `invalid_or_revoked` | 403 | **يدمج `not_found` + `revoked` + `expired` معًا** الآن (كان `expired` منفصلة سابقًا) — إصلاح H1، Fail Closed كامل |
| `device_limit` | 403 | لا يظهر إلا بعد نجاح فك تشفير فعلي (إصلاح R1 — يمنع كشفه لمهاجم بلا مفتاح صحيح) |
| `decrypt_error` | 400 | يشمل base64 تالف أو مفتاح/بيانات غير متطابقة |
| `server_misconfigured` | 500 | متغيرات Supabase غير مضبوطة عند الإقلاع |
| **`backend_unavailable`** | **500** | **جديد (إصلاح #19)** — فشل اتصال/طلب فعلي بـSupabase أثناء التشغيل (لا الإقلاع)، بلا أي Stack Trace متسرّب |

### `POST /admin/create` — مُرحَّلة لـSupabase
**مدخل:** `{label, max_devices, expire_days, trial}` + Header `X-Admin-Token`
**مخرج:** `{ok: true, code, key_b64}` أو `{ok: false, reason}` (`unauthorized` 401 / `server_misconfigured` 500 / `backend_unavailable` 500)

### `POST /admin/revoke` — محدَّثة (إصلاح C1)
**مدخل:** `{code}` + Header `X-Admin-Token`
**السلوك الجديد:** تُحدِّث `licenses.json` المحلي **و**Supabase معًا (عبر `admin_force_revoke`، بلا فحص ملكية). `not_found` (404) فقط لو غير موجود بكلا المصدرين. `backend_unavailable` (500) لو فشل الاتصال الفعلي بـSupabase.
**⚠️ حالة انتقالية:** لا يزال `licenses.json` طرفًا بالمعادلة — الحذف الكامل مهمة Phase 2 الأولى الجارية.

### `POST /admin/pause_all` — محدَّثة (إصلاح C1)
**مدخل:** `{}` + Header `X-Admin-Token`
**المخرج:** `{ok: true, count, supabase_count}` — `count` من `licenses.json`، `supabase_count` من `admin_pause_all()` (يعتمد على `CodeQueryRepository` مُهيَّأة).

### `POST /admin/extend`, `GET /admin/list` — **لم تُرحَّلا بعد**
لا تزالان تعتمدان `licenses.json` حصرًا. **مهمة Phase 2 الأولى الجارية.**

### `POST /admin/decrypt` — مخطَّطة (Backlog)
### `GET /customer/status` — مخطَّطة (Backlog)

---

## مخطط قاعدة البيانات (Supabase) — بلا تغيير بهذي الجولة

جداول `codes`, `devices` كما موثَّقة سابقًا. `moderators` (Phase 2) موجودة بـ`migrations/001_phase2_moderator_schema.sql`، **غير مُطبَّقة حيًا بعد**.

### دوال RPC — بلا إضافة جديدة بهذي الجولة الأمنية
كل إصلاحات R1/C1/H1-H6/L1-L2/#19 نُفِّذت **حصرًا على مستوى Python** — صفر لمسة لمخطط قاعدة البيانات أو RPC جديدة.
