from __future__ import annotations

import unittest
import sys
import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1] / "nikki-router-setup"
sys.path.insert(0, str(TOOL_ROOT))

from katovpn_router_setup.setup import _parse_probe, _probe_command, inspect_router_setup  # noqa: E402
import katovpn_router_setup.core as core_module  # noqa: E402
from katovpn_router_setup.core import ConnectionSpec, SetupError  # noqa: E402

VALID_RUNTIME = b"mode: rule\nproxies:\n  - name: route\n    type: direct\nrules: []\n"


def assessment_flags(**overrides: object) -> str:
    flags: dict[str, object] = {
        "evidence_version": "1",
        "nikki_package": 0,
        "luci_package": 0,
        "mihomo_binary": 0,
        "mihomo_valid": 0,
        "nikki_init": 0,
        "nikki_config": 0,
        "enabled": 0,
        "active_subscription": 0,
        "managed_marker": 0,
        "managed_name": 0,
        "managed_user_agent": 0,
        "tcp_redirect": 0,
        "udp_tproxy": 0,
        "ipv4_dns_hijack": 0,
        "ipv6_proxy_disabled": 0,
        "tun_dns_hijack_disabled": 0,
        "tproxy_mark": 0,
        "dns_contract": 0,
        "proxy_contract": 0,
        "policy_contract": 0,
        "service_running": 0,
        "mihomo_running": 0,
        "nft_redirect": 0,
        "nft_tproxy": 0,
        "policy_routing": 0,
        "dns_listener": 0,
        "subscription_file": 0,
        "runtime_file": 0,
        "external_services": "",
        "dnsmasq_forwarding": 0,
        "dhcp_dns": 0,
        "network_dns": 0,
        "dnsmasq_override": 0,
    }
    flags.update(overrides)
    return "\n".join(f"{key}={value}" for key, value in flags.items())


COMPLETE_COMPONENTS = {
    "nikki_package": 1,
    "luci_package": 1,
    "mihomo_binary": 1,
    "mihomo_valid": 1,
    "nikki_init": 1,
    "nikki_config": 1,
}

MANAGED_READY = {
    **COMPLETE_COMPONENTS,
    "enabled": 1,
    "active_subscription": 1,
    "managed_marker": 1,
    "managed_name": 1,
    "managed_user_agent": 1,
    "tcp_redirect": 1,
    "udp_tproxy": 1,
    "ipv4_dns_hijack": 1,
    "ipv6_proxy_disabled": 1,
    "tun_dns_hijack_disabled": 1,
    "tproxy_mark": 1,
    "dns_contract": 1,
    "proxy_contract": 1,
    "policy_contract": 1,
    "service_running": 1,
    "mihomo_running": 1,
    "nft_redirect": 1,
    "nft_tproxy": 1,
    "policy_routing": 1,
    "dns_listener": 1,
    "subscription_file": 1,
    "runtime_file": 1,
}


class AssessmentSession:
    def __init__(
        self,
        output: str,
        fingerprint: str = "SHA256:unit-test-router",
        runtime_document: bytes = VALID_RUNTIME,
    ) -> None:
        self.output = output
        self.fingerprint = fingerprint
        self.runtime_document = runtime_document
        self.calls: list[tuple[str, str]] = []
        self.connected = False
        self.closed = False

    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.closed = True

    def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
        del timeout, check
        self.calls.append((label, command))
        return self.output

    def read_file(self, remote_path: str, *, max_bytes: int = 5 * 1024 * 1024) -> bytes:
        del max_bytes
        self.calls.append(("runtime document", remote_path))
        return self.runtime_document


@contextmanager
def replaced_core_functions(**replacements: object):
    originals = {name: getattr(core_module, name) for name in replacements}
    try:
        for name, replacement in replacements.items():
            setattr(core_module, name, replacement)
        yield
    finally:
        for name, original in originals.items():
            setattr(core_module, name, original)


class RouterSetupModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ConnectionSpec(
            host="192.168.1.1",
            username="root",
            password="test-password",
            subscription_url="https://subscribe.example.test/tokenized-path",
        )

    def test_setup_assessment_module_exists(self) -> None:
        self.assertTrue((TOOL_ROOT / "katovpn_router_setup" / "setup.py").is_file())

    def test_clean_router_needs_install(self) -> None:
        session = AssessmentSession(assessment_flags())

        result = inspect_router_setup(session)

        self.assertEqual("needs_install", result["state"])
        self.assertEqual("install", result["action"])
        self.assertEqual("Нужно настроить роутер для работы с KatoVPN", result["message"])
        self.assertEqual([], result["warnings"])
        self.assertEqual(1, len(session.calls))
        self.assertEqual("состояние автоматической настройки", session.calls[0][0])

    def test_installed_inactive_manual_nikki_needs_configuration(self) -> None:
        result = inspect_router_setup(AssessmentSession(assessment_flags(**COMPLETE_COMPONENTS)))

        self.assertEqual("needs_configuration", result["state"])
        self.assertEqual("configure", result["action"])
        self.assertEqual("complete", result["details"]["components"])
        self.assertFalse(result["details"]["managed"])

    def test_proven_managed_runtime_is_ready_for_refresh(self) -> None:
        result = inspect_router_setup(AssessmentSession(assessment_flags(**MANAGED_READY)))

        self.assertEqual("ready", result["state"])
        self.assertEqual("refresh", result["action"])
        self.assertTrue(result["details"]["configuration_verified"])
        self.assertTrue(result["details"]["runtime_verified"])
        self.assertNotIn("url", result["details"])

    def test_partial_install_needs_package_repair(self) -> None:
        result = inspect_router_setup(
            AssessmentSession(assessment_flags(nikki_package=1, nikki_init=1, nikki_config=1))
        )

        self.assertEqual("needs_repair", result["state"])
        self.assertEqual("install", result["action"])
        self.assertEqual("partial", result["details"]["components"])

    def test_managed_configuration_drift_needs_configuration_repair(self) -> None:
        drifted = {**MANAGED_READY, "tcp_redirect": 0, "nft_redirect": 0}

        result = inspect_router_setup(AssessmentSession(assessment_flags(**drifted)))

        self.assertEqual("needs_repair", result["state"])
        self.assertEqual("configure", result["action"])
        self.assertTrue(result["details"]["managed"])
        self.assertFalse(result["details"]["configuration_verified"])

    def test_marker_and_runtime_files_do_not_hide_transport_or_runtime_drift(self) -> None:
        for override, runtime_document in (
            ({"dns_contract": 0}, VALID_RUNTIME),
            ({"proxy_contract": 0}, VALID_RUNTIME),
            ({}, b"not: [valid"),
        ):
            drifted = {**MANAGED_READY, **override}
            with self.subTest(override=override, runtime_document=runtime_document):
                result = inspect_router_setup(
                    AssessmentSession(assessment_flags(**drifted), runtime_document=runtime_document)
                )
                self.assertEqual("needs_repair", result["state"])
                self.assertFalse(result["details"]["runtime_verified"])

    def test_external_dns_and_proxy_settings_warn_without_blocking(self) -> None:
        session = AssessmentSession(
            assessment_flags(
                **MANAGED_READY,
                external_services="adguardhome,openclash",
                dnsmasq_forwarding=1,
                dhcp_dns=1,
            )
        )

        result = inspect_router_setup(session)

        self.assertEqual("ready", result["state"])
        self.assertEqual(
            [{
                "code": "external_network_settings",
                "message": "На роутере обнаружены дополнительные сетевые настройки. Они могут влиять на работу KatoVPN.",
            }],
            result["warnings"],
        )
        self.assertEqual(
            ["active_dns_or_proxy_service", "custom_dhcp_dns", "custom_dnsmasq_forwarding"],
            result["details"]["warning_reasons"],
        )
        self.assertIn("adguardhome", result["details"]["external_services"])
        self.assertNotIn("/etc/config/nikki", session.calls[0][1])

    def test_custom_wan_dns_and_dnsmasq_overrides_are_external_warnings(self) -> None:
        result = inspect_router_setup(
            AssessmentSession(
                assessment_flags(**MANAGED_READY, network_dns=1, dnsmasq_override=1)
            )
        )

        self.assertEqual("ready", result["state"])
        self.assertEqual(
            ["custom_dnsmasq_options", "custom_network_dns"],
            result["details"]["warning_reasons"],
        )

    def test_missing_probe_evidence_is_unknown_and_blocked(self) -> None:
        session = AssessmentSession("evidence_version=1\nnikki_package=0")

        result = inspect_router_setup(session)

        self.assertEqual("unknown", result["state"])
        self.assertEqual("blocked", result["action"])
        self.assertFalse(result["details"]["evidence_complete"])

    def test_probe_executes_in_shell_without_evaluating_uci_values(self) -> None:
        shell = Path("C:/Program Files/Git/bin/sh.exe")
        if not shell.is_file():
            self.skipTest("Git shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            sentinel = temp / "must-not-exist"
            uci = temp / "uci"
            uci.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  '-q get nikki.config.profile') printf '%s' 'subscription:cfg123' ;;\n"
                "  '-q get nikki.cfg123') printf '%s' 'subscription' ;;\n"
                "  '-q get nikki.cfg123.kato_managed') printf '%s' '1' ;;\n"
                "  '-q get nikki.cfg123.name') printf '%s' '$(touch \"$KATO_SENTINEL\")' ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
                newline="\n",
            )
            uci.chmod(0o755)
            env = dict(os.environ)
            env["KATO_SENTINEL"] = str(sentinel)
            env["PATH"] = str(temp) + os.pathsep + env.get("PATH", "")

            completed = subprocess.run(
                [str(shell), "-c", _probe_command()],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                timeout=15,
                check=False,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        parsed = _parse_probe(completed.stdout)
        self.assertIsNotNone(parsed)
        self.assertIn("network_dns", parsed[0])
        self.assertNotIn("mihomo -t", _probe_command())
        self.assertFalse(sentinel.exists())

    def test_automatic_setup_fails_closed_on_unknown_fresh_inspection(self) -> None:
        session = AssessmentSession("evidence_version=1\nnikki_package=0")

        with self.assertRaises(SetupError) as raised:
            core_module.setup_router_vpn(
                self.spec,
                session.fingerprint,
                session_factory=lambda _spec: session,
                subscription_fetcher=lambda _url: {"structure_ok": True},
                package_fetcher=lambda _firmware, _arch: {},
            )

        self.assertEqual("setup_assessment_unknown", raised.exception.code)
        self.assertTrue(session.connected)
        self.assertTrue(session.closed)

    def test_automatic_setup_rejects_changed_fingerprint_before_inspection(self) -> None:
        session = AssessmentSession(assessment_flags(), fingerprint="SHA256:changed-router")

        with self.assertRaises(SetupError) as raised:
            core_module.setup_router_vpn(
                self.spec,
                "SHA256:expected-router",
                session_factory=lambda _spec: session,
            )

        self.assertEqual("host_key_changed", raised.exception.code)
        self.assertEqual([], session.calls)

    def test_automatic_setup_routes_clean_and_partial_installs_through_hardened_installer(self) -> None:
        for initial in (
            assessment_flags(),
            assessment_flags(nikki_package=1, nikki_init=1, nikki_config=1),
        ):
            sessions = iter([
                AssessmentSession(initial),
                AssessmentSession(assessment_flags(**MANAGED_READY)),
            ])
            captured: dict[str, object] = {}

            def fake_install(spec: ConnectionSpec, fingerprint: str, **kwargs: object) -> dict[str, object]:
                captured.update({"spec": spec, "fingerprint": fingerprint, **kwargs})
                verified = kwargs["verify_setup"](next(sessions))
                return {"status": "success", "operation": "install", "packages_installed": True, "setup": verified}

            with replaced_core_functions(install_router_vpn=fake_install):
                result = core_module.setup_router_vpn(
                    self.spec,
                    "SHA256:unit-test-router",
                    session_factory=lambda _spec: next(sessions),
                    subscription_fetcher=lambda _url: {"structure_ok": True},
                    package_fetcher=lambda _firmware, _arch: {"status": "available"},
                )

            self.assertEqual("install", result["setup_action"])
            self.assertEqual("setup", result["operation"])
            self.assertEqual("verified", result["verification"]["configuration"])
            self.assertEqual("not_tested", result["verification"]["lan_connectivity"])
            self.assertEqual("ready", result["setup"]["state"])
            self.assertIs(captured["spec"], self.spec)

    def test_automatic_setup_configures_manual_nikki_without_package_update(self) -> None:
        sessions = iter([
            AssessmentSession(assessment_flags(**COMPLETE_COMPONENTS)),
            AssessmentSession(assessment_flags(**MANAGED_READY)),
        ])
        captured: dict[str, object] = {}

        def fake_configure(spec: ConnectionSpec, fingerprint: str, **kwargs: object) -> dict[str, object]:
            captured.update({"spec": spec, "fingerprint": fingerprint, **kwargs})
            verified = kwargs["verify_setup"](next(sessions))
            return {"status": "success", "component_updates": {"nikki": None, "mihomo": None}, "setup": verified}

        with replaced_core_functions(configure_router=fake_configure):
            result = core_module.setup_router_vpn(
                self.spec,
                "SHA256:unit-test-router",
                session_factory=lambda _spec: next(sessions),
                subscription_fetcher=lambda _url: {"structure_ok": True},
                package_fetcher=lambda *_args: self.fail("manual configuration must not fetch packages"),
            )

        self.assertEqual("configure", result["setup_action"])
        self.assertFalse(captured.get("update_nikki", False))
        self.assertFalse(captured.get("update_mihomo", False))

    def test_automatic_setup_refreshes_only_proven_ready_configuration(self) -> None:
        sessions = iter([
            AssessmentSession(assessment_flags(**MANAGED_READY, dnsmasq_forwarding=1)),
            AssessmentSession(assessment_flags(**MANAGED_READY, dnsmasq_forwarding=1)),
        ])
        captured: dict[str, object] = {}

        def fake_refresh(spec: ConnectionSpec, fingerprint: str, **kwargs: object) -> dict[str, object]:
            captured.update({"spec": spec, "fingerprint": fingerprint, **kwargs})
            verified = kwargs["verify_setup"](next(sessions))
            return {"status": "success", "operation": "subscription", "setup": verified}

        with replaced_core_functions(replace_router_subscription=fake_refresh):
            result = core_module.setup_router_vpn(
                self.spec,
                "SHA256:unit-test-router",
                session_factory=lambda _spec: next(sessions),
                subscription_fetcher=lambda _url: {"structure_ok": True},
                package_fetcher=lambda *_args: self.fail("refresh must not fetch packages"),
            )

        self.assertEqual("refresh", result["setup_action"])
        self.assertEqual("external_network_settings", result["warnings"][0]["code"])
        self.assertIs(captured["spec"], self.spec)


if __name__ == "__main__":
    unittest.main()
