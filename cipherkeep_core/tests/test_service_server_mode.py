"""
اختبارات ServerModeService وcrypto.py — بمعزل تام عن أي شبكة أو
Supabase، باستخدام المستودعات الوهمية + بلوب تشفير حقيقي نبنيه هنا
يدويًا (بنفس تنسيق encryptor.py) لأغراض الاختبار فقط.
"""

import sys
import os
import struct
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cipherkeep_core import CipherKeepCore, ServerModeService
from cipherkeep_core.crypto import MAGIC, HEADER_FMT, decrypt_blob, DecryptError
from cipherkeep_core.fakes import FakeCodeRepository, FakeDeviceRepository


def _build_test_blob(key: bytes, filename: str, source: bytes) -> bytes:
    """يبني بلوب مشفّر بنفس تنسيق encryptor.py، لأغراض الاختبار فقط."""
    name_bytes = filename.encode("utf-8")
    inner = struct.pack(">H", len(name_bytes)) + name_bytes + source
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, inner, associated_data=MAGIC)
    header = struct.pack(HEADER_FMT, MAGIC, 2, 3, 0, b"\x00" * 16, nonce)
    return header + ciphertext


class TestCryptoModule(unittest.TestCase):
    def test_decrypt_blob_roundtrip_succeeds(self):
        key = os.urandom(32)
        blob = _build_test_blob(key, "hello.py", b"print('hi')")
        name, data = decrypt_blob(blob, key)
        self.assertEqual(name, "hello.py")
        self.assertEqual(data, b"print('hi')")

    def test_decrypt_blob_wrong_key_raises_decrypt_error(self):
        right_key = os.urandom(32)
        wrong_key = os.urandom(32)
        blob = _build_test_blob(right_key, "hello.py", b"print('hi')")
        with self.assertRaises(DecryptError):
            decrypt_blob(blob, wrong_key)

    def test_decrypt_blob_garbage_input_raises_decrypt_error(self):
        with self.assertRaises(DecryptError):
            decrypt_blob(b"not a valid blob at all", os.urandom(32))

    def test_decrypt_blob_empty_input_raises_decrypt_error(self):
        with self.assertRaises(DecryptError):
            decrypt_blob(b"", os.urandom(32))


class TestServerModeService(unittest.TestCase):
    def setUp(self):
        self.codes = FakeCodeRepository()
        self.devices = FakeDeviceRepository(self.codes)
        self.core = CipherKeepCore(self.codes, self.devices)
        self.service = ServerModeService(self.core)

    def test_successful_verify_and_decrypt(self):
        key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=key, max_devices=1)
        blob = _build_test_blob(key, "secret.py", b"x = 1")

        result = self.service.verify_and_decrypt("ABC-123", "device-1", blob)

        self.assertTrue(result.ok)
        self.assertEqual(result.filename, "secret.py")
        self.assertEqual(result.source_bytes, b"x = 1")
        self.assertTrue(result.is_new_device)

    def test_second_verify_same_device_is_not_new(self):
        key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=key, max_devices=1)
        blob = _build_test_blob(key, "secret.py", b"x = 1")

        self.service.verify_and_decrypt("ABC-123", "device-1", blob)
        second = self.service.verify_and_decrypt("ABC-123", "device-1", blob)

        self.assertTrue(second.ok)
        self.assertFalse(second.is_new_device)

    def test_unknown_code_does_not_attempt_decrypt(self):
        result = self.service.verify_and_decrypt("GHOST", "device-1", b"garbage")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_found")

    def test_revoked_code_short_circuits_before_decrypt(self):
        key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=key, max_devices=1)
        self.codes._force_revoke("ABC-123")
        result = self.service.verify_and_decrypt("ABC-123", "device-1", b"garbage-ciphertext")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "revoked")

    def test_invalid_ciphertext_fails_before_device_limit_check(self):
        key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=key, max_devices=1)
        blob = _build_test_blob(key, "secret.py", b"x = 1")
        self.service.verify_and_decrypt("ABC-123", "device-1", blob)  # يملأ السلوت الوحيد

        result = self.service.verify_and_decrypt("ABC-123", "device-2", b"garbage")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "decrypt_error")

    def test_valid_device_but_corrupted_ciphertext_returns_decrypt_error(self):
        key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=key, max_devices=1)

        result = self.service.verify_and_decrypt("ABC-123", "device-1", b"not-a-real-blob")

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "decrypt_error")
        # بعد إصلاح R1: لا حجز يحدث إطلاقًا قبل نجاح فك التشفير.
        self.assertFalse(result.is_new_device)

    def test_wrong_key_material_returns_decrypt_error_not_crash(self):
        real_key = os.urandom(32)
        different_key = os.urandom(32)
        self.core.create_code("ABC-123", key_material=real_key, max_devices=1)
        blob = _build_test_blob(different_key, "secret.py", b"x = 1")

        result = self.service.verify_and_decrypt("ABC-123", "device-1", blob)

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "decrypt_error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
