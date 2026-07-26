"""
Data Access Layer — تنفيذ فعلي لواجهتي CodeRepository و DeviceRepository
باستخدام Supabase عبر PostgREST، بمكتبة requests فقط.

لماذا requests لا supabase-py/psycopg2:
    - صفر اعتماد على تجميع أصلي (native build) — قد يفشل على Termux/Pydroid.
    - requests أصلًا مستخدمة بكل مكونات المشروع الأخرى، لا تبعية جديدة.

الأسرار المطلوبة (متغيرات بيئة، لا تُخزَّن بأي مكان آخر):
    SUPABASE_URL            رابط المشروع (https://xxxx.supabase.co)
    SUPABASE_SERVICE_KEY    مفتاح service_role — سرّي تمامًا، سيرفر فقط،
                             يتجاوز RLS، يُمنع تسريبه لأي واجهة عميل
    CIPHERKEEP_MASTER_KEY   عبارة مرور تشفير key_material — سرّية، سيرفر فقط

كلا السرّين يعيشان حصرًا ببيئة بوت الإدارة، حسب Core Architecture البند 5.
"""

import os
import base64
from datetime import datetime
from typing import Optional

import requests

from cipherkeep_core.models import LicenseCode, DeviceClaimStatus, Moderator


class SupabaseConfigError(RuntimeError):
    """يُرفع عند غياب متغير بيئة مطلوب."""


class SupabaseRequestError(RuntimeError):
    """يُرفع عند فشل استدعاء Supabase (حالة HTTP غير ناجحة)."""


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SupabaseConfigError(f"متغير البيئة {name} غير موجود أو فارغ.")
    return value


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _check(resp: requests.Response, action: str) -> None:
    if resp.status_code >= 300:
        raise SupabaseRequestError(f"فشل {action}: HTTP {resp.status_code} — {resp.text}")


def _build_auth_headers(service_key: str) -> dict:
    """
    Supabase حديثًا يدعم تنسيقين للمفاتيح:
        - الجديد: sb_secret_... / sb_publishable_...  (ليس JWT)
        - القديم: JWT (يبدأ عادة بـ eyJ...)

    مع التنسيق الجديد، إرسال المفتاح بترويسة Authorization: Bearer
    يتسبب برفضه بمستوى قاعدة البيانات لأنه ليس JWT صالحًا — تكفي
    ترويسة apikey وحدها، والبوابة تتولى تحديد الصلاحية داخليًا.
    مع التنسيق القديم، لازم الترويستين معًا كما كان الحال دائمًا.
    """
    headers = {"apikey": service_key, "Content-Type": "application/json"}
    if not service_key.startswith("sb_"):
        headers["Authorization"] = f"Bearer {service_key}"
    return headers


class SupabaseCodeRepository:
    def __init__(
        self,
        base_url: Optional[str] = None,
        service_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self._base_url = (base_url or _require_env("SUPABASE_URL")).rstrip("/")
        self._service_key = service_key or _require_env("SUPABASE_SERVICE_KEY")
        self._passphrase = passphrase or _require_env("CIPHERKEEP_MASTER_KEY")
        self._session = session or requests
        self._headers = _build_auth_headers(self._service_key)

    def create(
        self,
        code: str,
        key_material: bytes,
        label: Optional[str],
        max_devices: int,
        trial: bool,
        expires_at: Optional[datetime],
        moderator_id: Optional[str] = None,
    ) -> None:
        payload = {
            "p_code": code,
            "p_key_material_b64": base64.b64encode(key_material).decode("ascii"),
            "p_label": label,
            "p_max_devices": max_devices,
            "p_trial": trial,
            "p_expires_at": expires_at.isoformat() if expires_at else None,
            "p_passphrase": self._passphrase,
            "p_moderator_id": moderator_id,
        }
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_create_code",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "إنشاء الكود بـ Supabase")

    def get(self, code: str) -> Optional[LicenseCode]:
        payload = {"p_code": code, "p_passphrase": self._passphrase}
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_get_code",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "جلب الكود من Supabase")
        rows = resp.json()
        if not rows:
            return None
        row = rows[0]
        return LicenseCode(
            code=row["code"],
            key_material=base64.b64decode(row["key_material_b64"]),
            label=row["label"],
            max_devices=row["max_devices"],
            trial=row["trial"],
            revoked=row["revoked"],
            expires_at=_parse_ts(row["expires_at"]),
            created_at=_parse_ts(row["created_at"]),
            # .get() بدل ["..."] عمدًا: يبقى متوافقًا مع صفوف قديمة/RPC
            # لم يُحدَّث بعد لإرجاع هذا الحقل (لحين تطبيق migration الحي).
            moderator_id=row.get("moderator_id"),
        )

    def revoke(self, code: str) -> None:
        """
        تحديث بسيط بلا فحص ملكية — نفس عقد الواجهة المجرَّدة تمامًا.
        فحص الملكية حدث فعلًا قبل هذا النداء داخل CipherKeepCore.
        """
        payload = {"p_code": code}
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_revoke_code",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "إلغاء الكود بـ Supabase")

    def extend(self, code: str, new_expires_at: datetime) -> None:
        """نفس الملاحظة أعلاه بـrevoke."""
        payload = {"p_code": code, "p_new_expires_at": new_expires_at.isoformat()}
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_extend_code",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "تمديد الكود بـ Supabase")


class SupabaseDeviceRepository:
    def __init__(
        self,
        base_url: Optional[str] = None,
        service_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self._base_url = (base_url or _require_env("SUPABASE_URL")).rstrip("/")
        self._service_key = service_key or _require_env("SUPABASE_SERVICE_KEY")
        self._session = session or requests
        self._headers = _build_auth_headers(self._service_key)

    def claim_device_slot(self, code: str, device_fingerprint: str, now: datetime) -> DeviceClaimStatus:
        payload = {
            "p_code": code,
            "p_device_fingerprint": device_fingerprint,
            "p_now": now.isoformat(),
        }
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_claim_device_slot",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "حجز سلوت الجهاز")

        raw = resp.json()
        # PostgREST يرجّع القيمة النصية للدالة الاسكالر مباشرة عادةً،
        # لكن نتعامل بمرونة مع احتمال تغليفها بقائمة — هذي التفصيلة
        # بالذات تحتاج تأكيدًا من الاختبار الحي (smoke_test_supabase.py)
        # لأني لا أقدر أتحقق من سلوك PostgREST الفعلي من بيئتي.
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None:
            raise SupabaseRequestError("استجابة فارغة غير متوقعة من ck_claim_device_slot")

        return DeviceClaimStatus(raw)


class SupabaseModeratorRepository:
    """
    تنفيذ فعلي لـModeratorRepository — لا يحتاج CIPHERKEEP_MASTER_KEY
    (بعكس SupabaseCodeRepository)، لأن moderators لا يحمل بيانات
    تحتاج تشفير عبر pgcrypto (لا key_material هنا).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        service_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self._base_url = (base_url or _require_env("SUPABASE_URL")).rstrip("/")
        self._service_key = service_key or _require_env("SUPABASE_SERVICE_KEY")
        self._session = session or requests
        self._headers = _build_auth_headers(self._service_key)

    def create(
        self,
        moderator_id: str,
        external_id: str,
        display_name: Optional[str],
        can_encrypt_server: bool,
        can_decrypt: bool,
    ) -> None:
        payload = {
            "p_moderator_id": moderator_id,
            "p_external_id": external_id,
            "p_display_name": display_name,
            "p_can_encrypt_server": can_encrypt_server,
            "p_can_decrypt": can_decrypt,
        }
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_register_moderator",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "تسجيل مشرف بـ Supabase")

    def get_by_external_id(self, external_id: str) -> Optional[Moderator]:
        payload = {"p_external_id": external_id}
        resp = self._session.post(
            f"{self._base_url}/rest/v1/rpc/ck_get_moderator_by_external_id",
            json=payload,
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "جلب المشرف من Supabase")
        rows = resp.json()
        if not rows:
            return None
        row = rows[0]
        return Moderator(
            moderator_id=row["moderator_id"],
            external_id=row["external_id"],
            display_name=row["display_name"],
            can_encrypt_server=row["can_encrypt_server"],
            can_decrypt=row["can_decrypt"],
            created_at=_parse_ts(row["created_at"]),
        )


class SupabaseCodeQueryRepository:
    """
    تنفيذ فعلي لـCodeQueryRepository — مضافة لإصلاح C1 (Kill Switch).

    بعكس SupabaseCodeRepository/SupabaseDeviceRepository (اللي تستدعي
    دوال RPC مخصَّصة)، هذي الطبقة تستخدم نقطة REST القياسية التلقائية
    لـPostgREST مباشرة (GET /rest/v1/codes?select=code) — بلا حاجة
    لكتابة أو تطبيق أي دالة SQL جديدة على Supabase. أي جدول Postgres
    مكشوف بمخطط public يُتاح تلقائيًا بهذي الطريقة ما لم يُعطَّل صراحة.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        service_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self._base_url = (base_url or _require_env("SUPABASE_URL")).rstrip("/")
        self._service_key = service_key or _require_env("SUPABASE_SERVICE_KEY")
        self._session = session or requests
        self._headers = _build_auth_headers(self._service_key)

    def list_all_codes(self):
        resp = self._session.get(
            f"{self._base_url}/rest/v1/codes",
            params={"select": "code"},
            headers=self._headers,
            timeout=15,
        )
        _check(resp, "سرد كل الأكواد من Supabase")
        rows = resp.json()
        return [row["code"] for row in rows]
