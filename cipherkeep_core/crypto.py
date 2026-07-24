"""
crypto.py — موديول تشفير مساعد فقط.

لا منطق أعمال، لا وصول بيانات، لا معرفة بأي كود/جهاز/قاعدة بيانات.
مسؤوليته الوحيدة: فك تشفير ملف .enc.py (وضع السيرفر)، بنفس التنسيق
الذي ينتجه encryptor.py حرفيًا.

⚠️ الثوابت MAGIC و HEADER_FMT يجب أن تبقى متطابقة تمامًا مع
encryptor.py الأصلي — أي اختلاف يكسر فك التشفير لكل الملفات
الموجودة فعليًا لدى العملاء.
"""

import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"SFCL0002"
HEADER_FMT = ">8sBBB16s12s"
HEADER_LEN = struct.calcsize(HEADER_FMT)


class DecryptError(Exception):
    """يُرفع عند أي فشل بفك التشفير — مفتاح خاطئ، بيانات تالفة، أو تنسيق غير متطابق."""


def decrypt_blob(blob: bytes, key: bytes) -> Tuple[str, bytes]:
    """
    يفك تشفير ملف .enc.py (وضع السيرفر)، يرجّع (filename, source_bytes).
    يرفع DecryptError عند أي فشل — لا يسرّب استثناءات مكتبة
    cryptography الخام لطبقات فوقية.
    """
    try:
        magic, _version, _mode, _n_log2, _salt, nonce = struct.unpack(
            HEADER_FMT, blob[:HEADER_LEN]
        )
        if magic != MAGIC:
            raise DecryptError("magic mismatch")

        ciphertext = blob[HEADER_LEN:]
        inner = AESGCM(key).decrypt(nonce, ciphertext, associated_data=magic)

        name_len = struct.unpack(">H", inner[:2])[0]
        name = inner[2:2 + name_len].decode("utf-8")
        data = inner[2 + name_len:]
        return name, data

    except DecryptError:
        raise
    except (InvalidTag, ValueError, struct.error, UnicodeDecodeError) as e:
        raise DecryptError(str(e)) from e
