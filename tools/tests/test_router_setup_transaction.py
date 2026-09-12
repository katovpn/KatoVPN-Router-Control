"""Final automatic assessment must remain inside Nikki rollback boundaries."""
import unittest
from unittest.mock import Mock

from tools.tests.test_nikki_router_setup import FakeSession
from katovpn_router_setup import core


class SetupTransactionTests(unittest.TestCase):
    def setUp(self):
        self.spec = core.ConnectionSpec("192.0.2.10", "root", "test-password", "https://setup.example.test/d/test-token")

    def test_failed_final_assessment_restores_previous_configuration(self):
        session = FakeSession(self.spec)

        def verify(current):
            self.assertIs(current, session)
            self.assertFalse(current.closed)
            raise core.SetupError("setup_verification_failed", "Final assessment failed")

        with self.assertRaises(core.SetupError) as caught:
            core.configure_router(self.spec, session.fingerprint, session_factory=lambda _: session,
                                  subscription_fetcher=lambda _: {}, verify_setup=verify)
        self.assertTrue(caught.exception.details["rolled_back"])
        self.assertIn("автоматический откат", session.labels)
        self.assertTrue(session.closed)

    def test_success_contains_assessment_from_same_open_session(self):
        session = FakeSession(self.spec)
        assessment = {"state": "ready", "action": "refresh", "warnings": []}
        def verify(current):
            self.assertFalse(current.closed)
            return assessment
        result = core.configure_router(self.spec, session.fingerprint, session_factory=lambda _: session,
                                       subscription_fetcher=lambda _: {}, verify_setup=verify)
        self.assertEqual(result["setup"], assessment)

    def test_failed_refresh_assessment_restores_disabled_state(self):
        class RefreshSession(FakeSession):
            def run(self, command, *, label, timeout=20, check=True):
                values = {"active Nikki subscription": "cfg123abc", "subscription download result": "1",
                          "active profile after subscription change": "subscription:cfg123abc", "исходное состояние": "0"}
                if label in values:
                    self.labels.append(label)
                    self.commands[label] = command
                    return values[label]
                return super().run(command, label=label, timeout=timeout, check=check)
        session = RefreshSession(self.spec)
        def verify(current):
            self.assertFalse(current.closed)
            raise core.SetupError("setup_verification_failed", "Final assessment failed")
        with self.assertRaises(core.SetupError) as caught:
            core.replace_router_subscription(self.spec, session.fingerprint, session_factory=lambda _: session,
                                             subscription_fetcher=lambda _: {}, verify_setup=verify)
        self.assertTrue(caught.exception.details["rolled_back"])
        self.assertIn("автоматический откат", session.labels)
        self.assertNotIn("reload Nikki profile", session.labels)

    def test_refresh_invalid_runtime_rolls_back_before_final_assessment(self):
        class InvalidRuntimeSession(FakeSession):
            def run(self, command, *, label, timeout=20, check=True):
                values = {"active Nikki subscription": "cfg123abc", "subscription download result": "1",
                          "active profile after subscription change": "subscription:cfg123abc",
                          "проверка конфигурации Mihomo": "invalid"}
                if label in values:
                    self.labels.append(label)
                    self.commands[label] = command
                    return values[label]
                return super().run(command, label=label, timeout=timeout, check=check)
        session = InvalidRuntimeSession(self.spec)
        verify = Mock()
        with self.assertRaises(core.SetupError) as caught:
            core.replace_router_subscription(self.spec, session.fingerprint, session_factory=lambda _: session,
                                             subscription_fetcher=lambda _: {}, verify_setup=verify)
        self.assertEqual(caught.exception.code, "mihomo_runtime_validation")
        self.assertTrue(caught.exception.details["rolled_back"])
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
