"""
تنفيذات وهمية بالذاكرة (In-Memory Fakes) لواجهات CodeRepository
و DeviceRepository — للاختبار فقط. تطابق نفس توقيع الواجهات
المجرَّدة تمامًا، بلا اتصال شبكي أو قاعدة بيانات حقيقية.

هذا هو السبب الهندسي المعتمد لـ DIP (البند 5 من Core Architecture):
اختبار منطق الأعمال بمعزل تام عن Supabase.
"""

from dataclasses import replace
from datetime import datetime
from typing import Dict, Optional, Tuple

from .models import LicenseCode, DeviceRecord, DeviceClaimStatus, Moderator


class FakeCodeRepository:
    def __init__(self) -> None:
        self._store: Dict[str, LicenseCode] = {}

    def create(
        self,
        code,
        key_material,
        label,
        max_devices,
        trial,
        expires_at,
        moderator_id=None,
    ) -> None:
        self._store[code] = LicenseCode(
            code=code,
            key_material=key_material,
            label=label,
            max_devices=max_devices,
            trial=trial,
            revoked=False,
            expires_at=expires_at,
            created_at=datetime.now(),
            moderator_id=moderator_id,
        )

    def get(self, code: str) -> Optional[LicenseCode]:
        return self._store.get(code)

    def revoke(self, code: str) -> None:
        """
        تحديث بسيط بلا فحص ملكية — نفس عقد الواجهة المجرَّدة تمامًا
        (فحص الملكية مسؤولية CipherKeepCore.revoke_code() حصرًا).
        """
        rec = self._store[code]
        self._store[code] = replace(rec, revoked=True)

    def extend(self, code: str, new_expires_at: datetime) -> None:
        """نفس الملاحظة أعلاه بـrevoke."""
        rec = self._store[code]
        self._store[code] = replace(rec, expires_at=new_expires_at)

    # --- أدوات مساعدة للاختبار فقط، ليست جزءًا من الواجهة المجرَّدة ---
    def _force_revoke(self, code: str) -> None:
        self._store[code] = replace(self._store[code], revoked=True)


class FakeDeviceRepository:
    """
    تنفيذ وهمي بالذاكرة. لا يحتاج قفلًا حقيقيًا لأن اختبارات الوحدة
    أحادية الخيط (single-threaded) بطبيعتها — الذرّية الفعلية تحت
    تزامن حقيقي مسؤولية التنفيذ الفعلي بـSupabase (ck_claim_device_slot)
    فقط، لا هذا الملف. هذا الفصل هو بالضبط ما يتيحه DIP.
    """

    def __init__(self, codes: "FakeCodeRepository") -> None:
        # يحتاج مرجعًا لمستودع الأكواد عشان يقرأ max_devices عبر
        # واجهته العامة (get)، بنفس الطريقة اللي تقرأ فيها الدالة
        # الذرية الفعلية بـSupabase من جدول codes ضمن نفس المعاملة.
        self._codes_repo = codes
        self._store: Dict[Tuple[str, str], DeviceRecord] = {}

    def count_for_code(self, code: str) -> int:
        return sum(1 for (c, _f) in self._store.keys() if c == code)

    def claim_device_slot(
        self, code: str, device_fingerprint: str, now: datetime
    ) -> DeviceClaimStatus:
        key = (code, device_fingerprint)
        existing = self._store.get(key)
        if existing is not None:
            self._store[key] = DeviceRecord(
                code=existing.code,
                device_fingerprint=existing.device_fingerprint,
                first_seen_at=existing.first_seen_at,
                last_seen_at=now,
            )
            return DeviceClaimStatus.ALREADY_REGISTERED

        max_devices = self._codes_repo.get(code).max_devices
        current_count = self.count_for_code(code)
        if current_count >= max_devices:
            return DeviceClaimStatus.LIMIT_REACHED

        self._store[key] = DeviceRecord(
            code=code,
            device_fingerprint=device_fingerprint,
            first_seen_at=now,
            last_seen_at=now,
        )
        return DeviceClaimStatus.REGISTERED


class FakeModeratorRepository:
    def __init__(self) -> None:
        self._store: Dict[str, Moderator] = {}  # مفتاح: external_id

    def create(
        self,
        moderator_id: str,
        external_id: str,
        display_name: Optional[str],
        can_encrypt_server: bool,
        can_decrypt: bool,
    ) -> None:
        self._store[external_id] = Moderator(
            moderator_id=moderator_id,
            external_id=external_id,
            display_name=display_name,
            can_encrypt_server=can_encrypt_server,
            can_decrypt=can_decrypt,
            created_at=datetime.now(),
        )

    def get_by_external_id(self, external_id: str) -> Optional[Moderator]:
        return self._store.get(external_id)


class FakeCodeQueryRepository:
    """
    تنفيذ وهمي بالذاكرة لـCodeQueryRepository — مضافة لإصلاح C1.
    يحتاج مرجعًا لـFakeCodeRepository عشان يقرأ كل الأكواد المخزَّنة،
    بنفس نمط FakeDeviceRepository اللي يحتاج مرجعًا لـFakeCodeRepository
    أصلًا لقراءة max_devices.
    """

    def __init__(self, codes: "FakeCodeRepository") -> None:
        self._codes_repo = codes

    def list_all_codes(self):
        return list(self._codes_repo._store.keys())
