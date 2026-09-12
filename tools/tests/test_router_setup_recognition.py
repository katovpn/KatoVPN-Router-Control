import unittest

from tools.tests.test_router_setup import AssessmentSession, MANAGED_READY, assessment_flags
from katovpn_router_setup.setup import inspect_router_setup, _probe_command


class RouterRecognitionTests(unittest.TestCase):
    def test_legacy_name_and_missing_marker_do_not_require_reconfiguration(self):
        flags = {**MANAGED_READY, "managed_marker": 0, "managed_name": 0}
        result = inspect_router_setup(AssessmentSession(assessment_flags(**flags)))
        self.assertEqual("ready", result["state"])
        self.assertEqual("refresh", result["action"])
        self.assertFalse(result["details"]["managed"])
        self.assertTrue(result["details"]["configuration_verified"])

    def test_unmarked_profile_still_requires_real_settings_and_contract_user_agent(self):
        for key in ("active_subscription", "managed_user_agent", "dns_contract", "policy_contract", "proxy_contract"):
            with self.subTest(key=key):
                flags = {**MANAGED_READY, "managed_marker": 0, "managed_name": 0, key: 0}
                result = inspect_router_setup(AssessmentSession(assessment_flags(**flags)))
                self.assertNotEqual("ready", result["state"])
                self.assertIn(key, result["details"]["configuration_mismatches"])

    def test_runtime_evidence_does_not_depend_on_profile_ownership_or_uci_contract(self):
        flags = {**MANAGED_READY, "managed_marker": 0, "policy_contract": 0}
        result = inspect_router_setup(AssessmentSession(assessment_flags(**flags)))
        self.assertFalse(result["details"]["configuration_verified"])
        self.assertTrue(result["details"]["runtime_checks_passed"])
        self.assertNotEqual("ready", result["state"])

    def test_dnsmasq_warning_identifies_exact_nonsecret_option(self):
        for key in ("dnsmasq_noresolv", "dnsmasq_dns_redirect", "dnsmasq_nonstandard_port"):
            with self.subTest(key=key):
                result = inspect_router_setup(AssessmentSession(assessment_flags(
                    **MANAGED_READY, dnsmasq_override=1, **{key: 1})))
                self.assertEqual([key], result["details"]["dnsmasq_options"])
                self.assertTrue(result["warnings"])
                self.assertIn(key, _probe_command())


if __name__ == "__main__":
    unittest.main()
