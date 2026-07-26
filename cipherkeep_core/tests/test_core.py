"""
اختبارات وحدة لـ CipherKeepCore، باستخدام المستودعات الوهمية فقط.
صفر اتصال شبكي، صفر Supabase حقيقية — نفس مبدأ DIP المعتمد.
"""

import sys
import os
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cipherkeep_core import CipherKeepCore, RepositoryNotConfigured
from cipherkeep_core.fakes import (
    FakeCodeRepository,
    FakeDeviceRepository,
    FakeModeratorRepository,
)


class TestCipherKeepCore(unittest.TestCase):
    def setUp(self):
        self.codes = FakeCodeRepository()
        self.devices = FakeDeviceRepository(self.codes)
        self.core = CipherKeepCore(self.codes, self.devices)

    def test_verify_unknown_code_returns_not_found(self):
        result = self.core.verify_code("GHOST-CODE", "device-1")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_found")
        self.assertIsNone(result.key_material)

    def test_create_then_verify_new_device_succeeds(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        result = self.core.verify_code("ABC-123", "device-1")
        self.assertTrue(result.ok)
        self.assertIsNone(result.reason)
        self.assertEqual(result.key_material, b"secret-key")
        self.assertEqual(self.devices.count_for_code("ABC-123"), 1)

    def test_same_device_verifying_twice_does_not_double_count(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        first = self.core.verify_code("ABC-123", "device-1")
        second = self.core.verify_code("ABC-123", "device-1")
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertEqual(self.devices.count_for_code("ABC-123"), 1)

    def test_second_new_device_beyond_max_is_rejected(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        first = self.core.verify_code("ABC-123", "device-1")
        second = self.core.verify_code("ABC-123", "device-2")
        self.assertTrue(first.ok)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "device_limit_reached")
        self.assertIsNone(second.key_material)
        # التأكد إن الجهاز المرفوض لم يُسجَّل فعليًا
        self.assertEqual(self.devices.count_for_code("ABC-123"), 1)

    def test_multiple_devices_allowed_up_to_max(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=3)
        r1 = self.core.verify_code("ABC-123", "device-1")
        r2 = self.core.verify_code("ABC-123", "device-2")
        r3 = self.core.verify_code("ABC-123", "device-3")
        r4 = self.core.verify_code("ABC-123", "device-4")
        self.assertTrue(r1.ok and r2.ok and r3.ok)
        self.assertFalse(r4.ok)
        self.assertEqual(r4.reason, "device_limit_reached")
        self.assertEqual(self.devices.count_for_code("ABC-123"), 3)

    def test_revoked_code_is_rejected_even_for_known_device(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        self.core.verify_code("ABC-123", "device-1")  # يسجّل الجهاز أول مرة
        self.codes._force_revoke("ABC-123")
        result = self.core.verify_code("ABC-123", "device-1")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "revoked")

    def test_expired_code_is_rejected(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, expires_at=past
        )
        result = self.core.verify_code("ABC-123", "device-1")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "expired")

    def test_not_yet_expired_code_succeeds(self):
        future = datetime.now(timezone.utc) + timedelta(days=1)
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, expires_at=future
        )
        result = self.core.verify_code("ABC-123", "device-1")
        self.assertTrue(result.ok)

    def test_code_without_expiry_never_expires(self):
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, expires_at=None
        )
        far_future = datetime.now(timezone.utc) + timedelta(days=3650)
        result = self.core.verify_code("ABC-123", "device-1", now=far_future)
        self.assertTrue(result.ok)

    def test_trial_flag_is_stored_but_does_not_block_verification(self):
        self.core.create_code(
            "TRIAL-1", key_material=b"trial-key", max_devices=1, trial=True
        )
        result = self.core.verify_code("TRIAL-1", "device-1")
        self.assertTrue(result.ok)
        stored = self.codes.get("TRIAL-1")
        self.assertTrue(stored.trial)


    def test_is_new_device_true_only_on_first_registration(self):
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=2)
        first = self.core.verify_code("ABC-123", "device-1")
        second = self.core.verify_code("ABC-123", "device-1")  # نفس الجهاز
        third = self.core.verify_code("ABC-123", "device-2")   # جهاز جديد ثانٍ

        self.assertTrue(first.is_new_device)
        self.assertFalse(second.is_new_device)
        self.assertTrue(third.is_new_device)

    # --- اختبارات revoke_code / extend_code (Phase 2 — جلسة تصميم صلاحيات المشرفين) ---

    def test_revoke_code_by_owning_moderator_succeeds(self):
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, moderator_id="mod-1"
        )
        result = self.core.revoke_code("ABC-123", moderator_id="mod-1")
        self.assertTrue(result.ok)
        self.assertIsNone(result.reason)
        # التأكد إن الإلغاء فعليًا حدث على السجل نفسه (لا مجرد رد نجاح بلا أثر)
        verify_after = self.core.verify_code("ABC-123", "device-1")
        self.assertFalse(verify_after.ok)
        self.assertEqual(verify_after.reason, "revoked")

    def test_revoke_code_by_different_moderator_is_rejected(self):
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, moderator_id="mod-1"
        )
        result = self.core.revoke_code("ABC-123", moderator_id="mod-2")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_owner")
        # التأكد إن الكود لم يُلغَ فعليًا رغم الرفض
        verify_after = self.core.verify_code("ABC-123", "device-1")
        self.assertTrue(verify_after.ok)

    def test_revoke_code_unknown_code_returns_not_found(self):
        result = self.core.revoke_code("GHOST-CODE", moderator_id="mod-1")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_found")

    def test_revoke_code_with_no_owner_is_rejected_for_any_moderator(self):
        # كود قديم (Phase 1)، أُنشئ بلا moderator_id — قرار افتراضي
        # محافظ: لا يُعتبَر متاحًا لأي مشرف، حتى لو كان الوحيد الموجود.
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        result = self.core.revoke_code("ABC-123", moderator_id="mod-1")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_owner")

    def test_extend_code_by_owning_moderator_succeeds(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, moderator_id="mod-1"
        )
        result = self.core.extend_code("ABC-123", moderator_id="mod-1", new_expires_at=future)
        self.assertTrue(result.ok)
        self.assertEqual(result.new_expires_at, future)
        stored = self.codes.get("ABC-123")
        self.assertEqual(stored.expires_at, future)

    def test_extend_code_by_different_moderator_is_rejected(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        self.core.create_code(
            "ABC-123", key_material=b"secret-key", max_devices=1, moderator_id="mod-1"
        )
        result = self.core.extend_code("ABC-123", moderator_id="mod-2", new_expires_at=future)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_owner")
        # التأكد إن expires_at لم يتغيّر فعليًا رغم الرفض
        stored = self.codes.get("ABC-123")
        self.assertIsNone(stored.expires_at)

    def test_extend_code_unknown_code_returns_not_found(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        result = self.core.extend_code("GHOST-CODE", moderator_id="mod-1", new_expires_at=future)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "not_found")

    def test_create_code_without_moderator_id_still_works_backward_compatible(self):
        # يضمن إن كل نداءات Phase 1 القديمة (بلا moderator_id) تبقى صحيحة
        self.core.create_code("ABC-123", key_material=b"secret-key", max_devices=1)
        stored = self.codes.get("ABC-123")
        self.assertIsNone(stored.moderator_id)

    # --- اختبارات ModeratorRepository (قرار معماري أثناء تنفيذ Phase 2) ---

    def test_core_without_moderator_repository_still_works_for_phase1_flows(self):
        # Core بمعاملين فقط (نمط Phase 1 القديم) — لا يجوز أن ينكسر
        codes = FakeCodeRepository()
        devices = FakeDeviceRepository(codes)
        core_no_moderators = CipherKeepCore(codes, devices)
        core_no_moderators.create_code("ABC-123", key_material=b"k", max_devices=1)
        result = core_no_moderators.verify_code("ABC-123", "device-1")
        self.assertTrue(result.ok)

    def test_resolve_moderator_without_repository_returns_none_not_crash(self):
        codes = FakeCodeRepository()
        devices = FakeDeviceRepository(codes)
        core_no_moderators = CipherKeepCore(codes, devices)
        self.assertIsNone(core_no_moderators.resolve_moderator("telegram-123"))

    def test_register_moderator_without_repository_raises_clear_error(self):
        codes = FakeCodeRepository()
        devices = FakeDeviceRepository(codes)
        core_no_moderators = CipherKeepCore(codes, devices)
        # RepositoryNotConfigured (لا RuntimeError عامة) -- إصلاح #19:
        # فصل شجرة الوراثة عمدًا يمنع تصادمًا مستقبليًا مع
        # SupabaseRequestError (وريثة RuntimeError) لو استُدعيت هذي
        # الدالة يومًا من Adapter يستخدم "except RuntimeError" عامة.
        with self.assertRaises(RepositoryNotConfigured):
            core_no_moderators.register_moderator("mod-1", "telegram-123")

    def test_register_then_resolve_moderator_by_external_id(self):
        moderators = FakeModeratorRepository()
        core = CipherKeepCore(self.codes, self.devices, moderators)
        core.register_moderator(
            "mod-1", "telegram-999", display_name="أحمد",
            can_encrypt_server=True, can_decrypt=False,
        )
        found = core.resolve_moderator("telegram-999")
        self.assertIsNotNone(found)
        self.assertEqual(found.moderator_id, "mod-1")
        self.assertTrue(found.can_encrypt_server)
        self.assertFalse(found.can_decrypt)

    def test_resolve_moderator_unknown_external_id_returns_none(self):
        moderators = FakeModeratorRepository()
        core = CipherKeepCore(self.codes, self.devices, moderators)
        self.assertIsNone(core.resolve_moderator("ghost-telegram-id"))

    def test_register_moderator_defaults_deny_permissions(self):
        # صلاحيات ترفض افتراضيًا (deny by default) لو لم تُحدَّد صراحة
        moderators = FakeModeratorRepository()
        core = CipherKeepCore(self.codes, self.devices, moderators)
        core.register_moderator("mod-1", "telegram-999")
        found = core.resolve_moderator("telegram-999")
        self.assertFalse(found.can_encrypt_server)
        self.assertFalse(found.can_decrypt)

    def test_end_to_end_moderator_owns_and_revokes_own_code(self):
        # سيناريو تكاملي: تسجيل مشرف → إنشاء كود باسمه → إلغاؤه بنجاح
        moderators = FakeModeratorRepository()
        core = CipherKeepCore(self.codes, self.devices, moderators)
        core.register_moderator("mod-1", "telegram-999", can_encrypt_server=True)
        moderator = core.resolve_moderator("telegram-999")

        core.create_code(
            "ABC-123", key_material=b"k", max_devices=1,
            moderator_id=moderator.moderator_id,
        )
        result = core.revoke_code("ABC-123", moderator_id=moderator.moderator_id)
        self.assertTrue(result.ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
