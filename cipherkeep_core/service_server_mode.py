"""
ServerModeService — خدمة مجال (Domain Service) خاصة بنمط "وضع
السيرفر" تحديدًا (أحد ثلاثة أنماط ثقة بـ encryptor.py الأصلي).

تعتمد على CipherKeepCore بالتركيب (Composition) فقط:
    - لا تُعدِّل CipherKeepCore ولا تضيف عليه شيئًا.
    - لا تنسخ أي منطق قرار موجود بداخله (صلاحية الكود، الإلغاء،
      الانتهاء، حد الأجهزة) — تستدعي verify_code وتبني فوق نتيجته.
    - تبعية cryptography (AESGCM) محصورة هنا + crypto.py، لا تصل
      إطلاقًا لـ core.py نفسه.

هذا النمط يسمح بإضافة خدمات مجال أخرى مستقبلًا (مثل نسخة إدارية من
فك التشفير) دون أي نمو إضافي على CipherKeepCore نفسه.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .core import CipherKeepCore
from .crypto import decrypt_blob, DecryptError
from .models import DeviceClaimStatus


@dataclass(frozen=True)
class DecryptedVerifyResult:
    """
    نتيجة verify_and_decrypt. نوع منفصل تمامًا عن VerifyResult —
    لا يلوّث عقد Core الأصلي بحقول خاصة بنمط واحد فقط.
    """
    ok: bool
    reason: Optional[str]
    filename: Optional[str]
    source_bytes: Optional[bytes]
    is_new_device: bool
    label: Optional[str] = None


class ServerModeService:
    def __init__(self, core: CipherKeepCore):
        self._core = core

    def verify_and_decrypt(
        self,
        code: str,
        device_fingerprint: str,
        ciphertext: bytes,
        now: Optional[datetime] = None,
    ) -> DecryptedVerifyResult:
        result = self._core.check_code_validity(code, now=now)

        if not result.ok:
            return DecryptedVerifyResult(
                ok=False, reason=result.reason, filename=None,
                source_bytes=None, is_new_device=False,
            )

        try:
            filename, source_bytes = decrypt_blob(ciphertext, result.key_material)
        except DecryptError:
            return DecryptedVerifyResult(
                ok=False, reason="decrypt_error", filename=None,
                source_bytes=None, is_new_device=False,
            )

        reg = self._core.register_device(code, device_fingerprint, now=now)

        if not reg.ok:
            return DecryptedVerifyResult(
                ok=False, reason=reg.reason, filename=None,
                source_bytes=None, is_new_device=False,
            )

        if reg.claim_status == DeviceClaimStatus.LIMIT_REACHED:
            return DecryptedVerifyResult(
                ok=False, reason="device_limit_reached", filename=None,
                source_bytes=None, is_new_device=False,
            )

        return DecryptedVerifyResult(
            ok=True, reason=None, filename=filename, source_bytes=source_bytes,
            is_new_device=(reg.claim_status == DeviceClaimStatus.REGISTERED),
            label=result.label,
        )
