# 07 — العقود (API / Contracts)

## ما يُعتبَر "تعديل عقد" (Contract Change)

أي إضافة/حذف/تغيير نوع حقل بأي بنية بيانات هنا، أو تغيير شكل مدخل/مخرج أي نقطة HTTP. يحتاج موافقة مسبقة دائمًا (`03_RULES.md` #3) — الاستثناء الضيق (كشف معلومة محسوبة أصلًا) **أُغلق نهائيًا** بعد `VerifyResult`.

---

## عقود Core (بايثون)

### `VerifyResult` — **مُغلَق، لا إضافات جديدة**
```python
ok: bool
reason: Optional[str]        # not_found | revoked | expired | device_limit_reached
key_material: Optional[bytes]
is_new_device: bool = False  # معلومة محسوبة أصلًا، للقراءة فقط
label: Optional[str] = None  # معلومة محسوبة أصلًا، للقراءة فقط — آخر إضافة مسموحة
```

### `DecryptedVerifyResult` (داخل `ServerModeService`)
نوع منفصل تمامًا عن `VerifyResult` — لا يشترك معه ببنية الملف، فقط بالمصدر المنطقي.
```python
ok: bool
reason: Optional[str]           # نفس قيم VerifyResult + decrypt_error
filename: Optional[str]
source_bytes: Optional[bytes]
is_new_device: bool
label: Optional[str] = None
```

### `DeviceClaimStatus` (Enum)
```python
REGISTERED | ALREADY_REGISTERED | LIMIT_REACHED
```

### `RevokeResult` / `ExtendResult` (Phase 2 — منفَّذان كودًا، بانتظار إثبات حي)
عقدان مستقلان تمامًا عن `VerifyResult` (قرار جلسة تصميم Phase 2، `05_DECISIONS.md`) — لا يُوسَّعان مستقبلًا لخدمة عمليات إدارية أخرى، كل عملية جديدة تحصل على عقدها الخاص وقت بنائها.
```python
# RevokeResult
ok: bool
reason: Optional[str] = None   # 'not_found' | 'not_owner'

# ExtendResult
ok: bool
reason: Optional[str] = None          # 'not_found' | 'not_owner'
new_expires_at: Optional[datetime] = None
```

### `Moderator` (Phase 2 — منفَّذ كودًا، بانتظار إثبات حي)
```python
moderator_id: str
external_id: str                # معرّف خارجي مجرَّد — لا علاقة بمخطط 3-5 أحرف المعلَّق (06_TODO.md #4)
display_name: Optional[str]
can_encrypt_server: bool        # يرفض افتراضيًا (deny by default)
can_decrypt: bool               # يرفض افتراضيًا (deny by default)
created_at: datetime
```

### الواجهات المجرَّدة
```python
CodeRepository.create(code, key_material, label, max_devices, trial, expires_at, moderator_id=None) -> None
CodeRepository.get(code) -> Optional[LicenseCode]
CodeRepository.revoke(code) -> None          # Phase 2 — تحديث بسيط، فحص الملكية داخل Core حصرًا
CodeRepository.extend(code, new_expires_at) -> None  # Phase 2 — نفس الملاحظة

DeviceRepository.claim_device_slot(code, device_fingerprint, now) -> DeviceClaimStatus

# Phase 2 — منفَّذة كودًا، بانتظار إثبات حي
ModeratorRepository.create(moderator_id, external_id, display_name, can_encrypt_server, can_decrypt) -> None
ModeratorRepository.get_by_external_id(external_id) -> Optional[Moderator]
```

### دوال `CipherKeepCore` الجديدة (Phase 2)
```python
CipherKeepCore.__init__(codes, devices, moderators=None)  # moderators اختياري — توافق خلفي كامل

CipherKeepCore.revoke_code(code, moderator_id) -> RevokeResult
CipherKeepCore.extend_code(code, moderator_id, new_expires_at) -> ExtendResult
CipherKeepCore.register_moderator(moderator_id, external_id, display_name=None, can_encrypt_server=False, can_decrypt=False) -> None
CipherKeepCore.resolve_moderator(external_id) -> Optional[Moderator]
```

---

## نقاط HTTP

### `POST /verify` — مُرحَّلة لـSupabase
**مدخل:** `{code, device_id, ciphertext_b64}`

**مخرج نجاح (200):** `{ok: true, name, source_b64}`

**مخرج فشل:**
| reason | HTTP | ملاحظة |
|---|---|---|
| `rate_limited` | 429 | فحص IP، مستوى Adapter بحت |
| `invalid_or_revoked` | 403 | يدمج `not_found` و`revoked` من Core عمدًا |
| `expired` | 403 | — |
| `device_limit` | 403 | — |
| `decrypt_error` | 400 | يشمل base64 تالف أو مفتاح/بيانات غير متطابقة |
| `server_misconfigured` | 500 | جديد — متغيرات Supabase غير مضبوطة، لا يمس نشرًا مُهيَّأ صح |

### `POST /admin/create` — مُرحَّلة لـSupabase
**مدخل:** `{label, max_devices, expire_days, trial}` + Header `X-Admin-Token`

**مخرج:** `{ok: true, code, key_b64}` أو `{ok: false, reason}` (`unauthorized` 401 / `server_misconfigured` 500)

### `POST /admin/revoke`, `POST /admin/extend`, `POST /admin/pause_all`, `GET /admin/list` — لم تُرحَّل
تعتمد `licenses.json` المحلي حاليًا، بقرار واعٍ (`05_DECISIONS.md`). عقودها لم تتغيّر عن التصميم الأصلي.

### `POST /admin/decrypt` — مخطَّطة (Backlog)
مدخل موثَّق كمالك + بيانات مشفَّرة. لا يمس عداد الأجهزة، لا إشعار عميل. التفاصيل الكاملة غير محسومة بعد.

### `GET /customer/status` — مخطَّطة (Backlog)
مدخل: الكود فقط. مخرج: حالة/انتهاء/استخدام أجهزة — أبدًا لا المفتاح نفسه. آلية Rate Limiting غير محسومة (`06_TODO.md`).

---

## مخطط قاعدة البيانات (Supabase)

### جدول `codes`
```
code            text PRIMARY KEY
key_material    bytea NOT NULL   -- مشفَّر عبر pgcrypto
label           text
max_devices     integer NOT NULL DEFAULT 1
trial           boolean NOT NULL DEFAULT false
revoked         boolean NOT NULL DEFAULT false
expires_at      timestamptz      -- NULL = بلا انتهاء
created_at      timestamptz NOT NULL DEFAULT now()
moderator_id    text             -- ⚠️ Phase 2، nullable، بلا FK بعد (migrations/phase2_moderator_schema_migration.sql)
```

### جدول `devices`
```
id                  bigserial PRIMARY KEY
code                text NOT NULL REFERENCES codes(code)
device_fingerprint  text NOT NULL
first_seen_at       timestamptz NOT NULL
last_seen_at        timestamptz NOT NULL
```

### جدول `moderators` — ⚠️ Phase 2، منفَّذ بـSQL (`migrations/`)، لم يُطبَّق حيًا بعد
```
moderator_id         text PRIMARY KEY
external_id          text NOT NULL UNIQUE
display_name         text
can_encrypt_server    boolean NOT NULL DEFAULT false
can_decrypt           boolean NOT NULL DEFAULT false
created_at            timestamptz NOT NULL DEFAULT now()
```

### دالة RPC: `ck_claim_device_slot`
عملية ذرية (قفل صف `codes`)، ترجّع نص ثابت من ثلاث قيم مطابقة لـ`DeviceClaimStatus`. التفاصيل الكاملة والمنطق بـ`01_ARCHITECTURE.md` القسم 5.

### دوال RPC إدارية — Phase 2 (⚠️ SQL جاهز بـ`migrations/`، لم يُطبَّق حيًا بعد)
- `ck_revoke_code(p_code)` — تحديث بسيط (`revoked=true`)، بلا فحص ملكية (يحدث داخل Core قبل الاستدعاء)
- `ck_extend_code(p_code, p_new_expires_at)` — تحديث بسيط، نفس الملاحظة أعلاه
- `ck_register_moderator(p_moderator_id, p_external_id, p_display_name, p_can_encrypt_server, p_can_decrypt)`
- `ck_get_moderator_by_external_id(p_external_id)`
