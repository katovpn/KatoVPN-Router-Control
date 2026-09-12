from __future__ import annotations

import json
import inspect
import sys
import threading
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1] / "nikki-router-setup"
sys.path.insert(0, str(TOOL_ROOT))

import katovpn_router_setup.core as core_module  # noqa: E402
import katovpn_router_setup.server as server_module  # noqa: E402
from katovpn_router_setup.setup import inspect_router_setup  # noqa: E402

from katovpn_router_setup.core import (  # noqa: E402
    ConnectionSpec,
    PROFILE_NAME,
    SetupError,
    USER_AGENT,
    configure_router,
    fetch_latest_nikki_packages,
    fetch_latest_nikki_release,
    preflight_router,
    profile_template_path,
    validate_inputs,
    validate_portable_template,
    validate_subscription_document,
    fetch_and_validate_subscription,
    restore_router_backup,
    install_router_vpn,
    validate_backup_id,
)


VALID_PROFILE = """
mode: rule
tun:
  enable: false
dns:
  enable: true
proxies:
  - name: "🇳🇱 Нидерланды"
    type: direct
proxy-groups:
  - name: "⚡️ Авто"
    type: select
    proxies: ["🇳🇱 Нидерланды"]
rules:
  - MATCH,⚡️ Авто
""".strip().encode("utf-8")

READY_SETUP_FLAGS = "\n".join(
    [
        "evidence_version=1",
        *(
            f"{key}=1"
            for key in (
                "nikki_package", "luci_package", "mihomo_binary", "mihomo_valid", "nikki_init", "nikki_config",
                "enabled", "active_subscription", "managed_marker", "managed_name", "managed_user_agent",
                "tcp_redirect", "udp_tproxy", "ipv4_dns_hijack", "ipv6_proxy_disabled",
                "tun_dns_hijack_disabled", "tproxy_mark", "dns_contract", "proxy_contract", "policy_contract",
                "service_running", "mihomo_running", "nft_redirect", "nft_tproxy", "policy_routing",
                "dns_listener", "subscription_file", "runtime_file", "runtime_config_valid",
            )
        ),
        "external_services=",
        "dnsmasq_forwarding=0",
        "dhcp_dns=0",
        "network_dns=0",
        "dnsmasq_override=0",
    ]
)


class FakeSession:
    def __init__(self, _spec: ConnectionSpec, *, fail_dns: bool = False, fail_restore_compare: bool = False):
        self.fingerprint = "SHA256:unit-test-router"
        self.fail_dns = fail_dns
        self.fail_restore_compare = fail_restore_compare
        self.connected = False
        self.closed = False
        self.writes: dict[str, bytes] = {}
        self.labels: list[str] = []
        self.commands: dict[str, str] = {}

    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.closed = True

    def run(self, _command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
        del timeout, check
        self.labels.append(label)
        self.commands[label] = _command
        responses = {
            "исходное состояние": "1",
            "backup Nikki": "",
            "импорт настроек Nikki": "cfg123abc",
            "перезапуск Nikki": "",
            "статус Nikki": "running",
            "процесс Mihomo": "yes",
            "таблица nftables": "table inet nikki { chain lan_redirect { } chain lan_tproxy { } }",
            "policy routing": "1024: from all fwmark 0x80/0xff lookup 80",
            "DNS listener": "udp UNCONN 0 0 [::]:1053 [::]:*",
            "активный профиль": "subscription:cfg123abc",
            "проверка конфигурации Mihomo": "valid",
            "состояние автоматической настройки": READY_SETUP_FLAGS,
            "очистка временных файлов": "",
            "автоматический откат": "",
            "проверка backup": "1",
            "восстановление backup": "",
            "проверка файла backup": "yes",
            "метаданные обновления": json.dumps(
                {"release": {"version": "24.10-SNAPSHOT"}}
            ),
            "пакеты обновления": (
                "Package: nikki\nVersion: 2025.12.21-r1\nArchitecture: aarch64_cortex-a53\n\n"
                "Package: luci-app-nikki\nVersion: 1.25.0-r1\nArchitecture: all\n\n"
                "Package: mihomo-meta\nVersion: 1.19.20\nArchitecture: aarch64_cortex-a53"
            ),
            "пакетный менеджер обновления": "opkg",
            "загрузка обновлений": "",
            "проверка установки обновлений": "__KATO_OPKG_EXIT__=0",
            "остановка Nikki": "",
            "установка Mihomo Core": "",
            "установка Nikki": "",
            "установка обновлений": "",
            "проверка обновления компонентов": (
                "mihomo-meta=1.19.29\nnikki=2026.04.08-r1\nluci-app-nikki=1.26.1-r1"
            ),
            "очистка пакетов обновления": "",
        }
        if label == "DNS listener" and self.fail_dns:
            return ""
        if label == "проверка файла backup" and self.fail_restore_compare:
            return "no"
        return responses.get(label, "")

    def write_file(self, remote_path: str, data: bytes, mode: str = "600") -> None:
        del mode
        self.writes[remote_path] = data

    def read_file(self, remote_path: str, *, max_bytes: int = 5 * 1024 * 1024) -> bytes:
        del remote_path, max_bytes
        return VALID_PROFILE


class FakePreflightSession(FakeSession):
    def run(self, _command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
        del timeout, check
        self.labels.append(label)
        if label == "сведения о роутере":
            return json.dumps(
                {
                    "kernel": getattr(self, "kernel_version", "6.6.119"),
                    "hostname": "router-test",
                    "model": "Test Router",
                    "board_name": "test,router",
                    "release": {"version": "24.10-SNAPSHOT", "description": "ImmortalWrt 24.10-SNAPSHOT"},
                }
            )
        return {
            "компоненты роутера": "uci=1\nfw4=1\nnft=1\nopkg=1\napk=0\nnikki_init=1\niptables=0",
            "версии Nikki и Mihomo": (
                "Package: nikki\nVersion: 2025.12.21-r1\nArchitecture: aarch64_cortex-a53\nStatus: install user installed\n\n"
                "Package: luci-app-nikki\nVersion: 1.25.0-r1\nStatus: install user installed\n\n"
                "Package: mihomo-meta\nVersion: 1.19.20\nArchitecture: aarch64_cortex-a53\nStatus: install user installed"
            ),
            "доступные обновления": "package_manager=opkg\nnikki_feed=0",
            "свободное место": "4096",
            "DNS redirect": "0",
            "статус Nikki": "running",
            "версия Mihomo Core": "Mihomo Meta v1.19.20 linux arm64 with go1.25",
            "текущий режим Nikki": "tcp=redirect\nudp=tproxy",
            "backups Nikki": "20260803-100000-deadbeef\t1785740400\t640\t1",
        }.get(label, "")


class NikkiRouterSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ConnectionSpec(
            host="192.168.1.1",
            username="root",
            password="test-password",
            subscription_url="https://subscribe.example.test/tokenized-path",
        )

    def test_router_network_inputs_are_strict_and_private(self) -> None:
        self.assertEqual("correct horse", core_module.validate_wifi_password("correct horse"))
        with self.assertRaises(SetupError):
            core_module.validate_wifi_password("short")
        with self.assertRaises(SetupError):
            core_module.validate_wifi_password("bad\npassword")

        self.assertEqual("192.168.50.1", core_module.validate_lan_ip("192.168.50.1", "255.255.255.0"))
        for value in ("8.8.8.8", "192.168.50.0", "192.168.50.255"):
            with self.assertRaises(SetupError):
                core_module.validate_lan_ip(value, "255.255.255.0")

    def test_timed_rollback_commands_never_embed_wifi_password(self) -> None:
        operation_id = "20260806-100000-deadbeef"
        rollback = core_module.build_wifi_rollback_command(operation_id)
        apply = core_module.build_wifi_apply_command(
            "default_radio0",
            "radio0",
            "RU",
            operation_id,
            password_changed=True,
        )

        self.assertIn("sleep 120", rollback)
        self.assertIn("sae-mixed", apply)
        self.assertIn("/tmp/kato-wifi-key", apply)
        self.assertIn("wireless.radio0.disabled='0'", apply)
        self.assertNotIn("correct horse", apply)
        self.assertIn("start-stop-daemon", rollback)
        self.assertIn("-m -p", rollback)
        self.assertIn("rollback.pid", rollback)

    def test_wifi_edit_preserves_password_when_blank(self) -> None:
        sessions: list[FakeSession] = []

        class WifiSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                return {
                    "проверка безопасной настройки Wi-Fi": (
                        "radio_type=mac80211\nmode=ap\ndevice=radio0\nrollback=1\n"
                        "sha256=1\nsae=1\nconfig_sha256=before-edit"
                    ),
                    "таймер отката Wi-Fi": "",
                    "изменение Wi-Fi": "",
                    "проверка Wi-Fi после изменения": (
                        "mode=ap\ndevice=radio1\ncountry=CN\nradio_enabled=1\n"
                        f"ssid_sha256={core_module.hashlib.sha256('Kato Edited'.encode('utf-8')).hexdigest()}"
                    ),
                    "подтверждение Wi-Fi": "",
                }.get(label, value)

        def factory(spec: ConnectionSpec) -> WifiSession:
            session = WifiSession(spec)
            sessions.append(session)
            return session

        result = core_module.change_wifi_configuration(
            self.spec,
            "SHA256:unit-test-router",
            radio="radio1",
            section="default_radio0",
            ssid="Kato Edited",
            password="",
            country="CN",
            session_factory=factory,
            sleep=lambda _seconds: None,
        )

        writes = {path: data for session in sessions for path, data in session.writes.items()}
        commands = {label: command for session in sessions for label, command in session.commands.items()}
        apply_command = commands["изменение Wi-Fi"]
        verify_command = commands["проверка Wi-Fi после изменения"]
        self.assertEqual("wifi_edit", result["operation"])
        self.assertFalse(result["password_changed"])
        self.assertEqual("Kato Edited", result["ssid"])
        self.assertEqual("radio1", result["radio"])
        self.assertEqual("CN", result["country"])
        self.assertNotIn("password", result)
        self.assertEqual(b"Kato Edited", writes["/tmp/kato-wifi-ssid"])
        self.assertNotIn("/tmp/kato-wifi-key", writes)
        self.assertNotIn("cat /tmp/kato-wifi-key", apply_command)
        self.assertNotIn(".key", apply_command)
        self.assertNotIn(".encryption", apply_command)
        self.assertIn("wireless.default_radio0.device=radio1", apply_command)
        self.assertIn("wireless.radio1.country=CN", apply_command)
        self.assertIn("wireless.default_radio0.mode", verify_command)
        self.assertIn("wireless.default_radio0.device", verify_command)
        self.assertIn("wireless.default_radio0.ssid", verify_command)
        self.assertIn("wireless.radio1.country", verify_command)
        self.assertNotIn("wireless.default_radio0.key", verify_command)

    def test_wifi_edit_replaces_password_without_exposing_it(self) -> None:
        sessions: list[FakeSession] = []
        replacement = "fixture-replacement-psk"
        ssid = "Kato Secure"
        ssid_hash = core_module.hashlib.sha256(ssid.encode("utf-8")).hexdigest()
        key_hash = core_module.hashlib.sha256(replacement.encode("utf-8")).hexdigest()

        class WifiSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                return {
                    "проверка безопасной настройки Wi-Fi": (
                        "radio_type=mac80211\nmode=ap\ndevice=radio0\nrollback=1\n"
                        "sha256=1\nsae=1\nconfig_sha256=before-edit"
                    ),
                    "таймер отката Wi-Fi": "",
                    "изменение Wi-Fi": "",
                    "проверка Wi-Fi после изменения": (
                        f"mode=ap\ndevice=radio1\ncountry=RU\nradio_enabled=1\nssid_sha256={ssid_hash}\n"
                        f"encryption=sae-mixed\nkey_sha256={key_hash}"
                    ),
                    "подтверждение Wi-Fi": "",
                }.get(label, value)

        def factory(spec: ConnectionSpec) -> WifiSession:
            session = WifiSession(spec)
            sessions.append(session)
            return session

        result = core_module.change_wifi_configuration(
            self.spec,
            "SHA256:unit-test-router",
            radio="radio1",
            section="default_radio0",
            ssid=ssid,
            password=replacement,
            country="RU",
            session_factory=factory,
            sleep=lambda _seconds: None,
        )

        writes = {path: data for session in sessions for path, data in session.writes.items()}
        commands = "\n".join(command for session in sessions for command in session.commands.values())
        verify_command = next(
            session.commands["проверка Wi-Fi после изменения"]
            for session in sessions
            if "проверка Wi-Fi после изменения" in session.commands
        )
        self.assertEqual(replacement.encode("utf-8"), writes["/tmp/kato-wifi-key"])
        self.assertEqual(ssid.encode("utf-8"), writes["/tmp/kato-wifi-ssid"])
        self.assertNotIn(replacement, commands)
        self.assertNotIn(replacement, json.dumps(result, ensure_ascii=False))
        self.assertEqual("wifi_edit", result["operation"])
        self.assertTrue(result["password_changed"])
        self.assertIn("wireless.default_radio0.key", verify_command)
        self.assertIn("wireless.default_radio0.encryption", verify_command)

    def test_wifi_create_still_rejects_an_empty_password(self) -> None:
        with self.assertRaises(SetupError) as raised:
            core_module.change_wifi_configuration(
                self.spec,
                "SHA256:unit-test-router",
                radio="radio0",
                ssid="Kato New",
                password="",
                country="RU",
                session_factory=lambda _spec: self.fail("invalid create must not connect"),
            )

        self.assertEqual("invalid_wifi_password", raised.exception.code)

    def test_router_password_change_uses_shadow_rollback_and_never_embeds_passwords(self) -> None:
        self.assertTrue(hasattr(core_module, "change_router_password"), "guarded router password operation is missing")

        sessions: list[FakeSession] = []
        seen_specs: list[ConnectionSpec] = []

        class PasswordSession(FakeSession):
            def __init__(self, spec: ConnectionSpec):
                super().__init__(spec)
                self.spec = spec

            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                return {
                    "проверка безопасной смены пароля": "uid=0\nrollback=1\nshadow=1\npasswd=1\nshadow_sha256=abc123",
                    "таймер отката пароля": "",
                    "смена пароля роутера": "",
                    "проверка нового пароля": "root",
                    "подтверждение нового пароля": "",
                }.get(label, value)

        def factory(spec: ConnectionSpec) -> PasswordSession:
            seen_specs.append(spec)
            session = PasswordSession(spec)
            sessions.append(session)
            return session

        new_password = "new-router-password-2026"
        result = core_module.change_router_password(
            self.spec,
            "SHA256:unit-test-router",
            new_password,
            session_factory=factory,
        )

        commands = "\n".join(command for session in sessions for command in session.commands.values())
        writes = {path: data for session in sessions for path, data in session.writes.items()}
        self.assertEqual("router_password", result["operation"])
        self.assertEqual(new_password.encode("utf-8"), writes["/tmp/kato-router-password"])
        self.assertNotIn(new_password, commands)
        self.assertNotIn(self.spec.password, commands)
        self.assertIn("/etc/shadow", commands)
        self.assertIn("start-stop-daemon", commands)
        self.assertIn("-m -p", commands)
        self.assertIn("rollback.pid", commands)
        self.assertEqual(new_password, seen_specs[-1].password)

    def test_vpn_log_export_has_allowlisted_sources(self) -> None:
        self.assertIn("source", inspect.signature(core_module.collect_router_logs).parameters)

        class LogSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                if label == "журнал VPN: Core Log":
                    return "core entry"
                return value

        fake = LogSession(self.spec)
        result = core_module.collect_router_logs(
            self.spec,
            fake.fingerprint,
            "connections",
            source="core",
            lines=300,
            session_factory=lambda _spec: fake,
        )

        command = fake.commands["журнал VPN: Core Log"]
        self.assertIn("/var/log/nikki/core.log", command)
        self.assertNotIn("/var/log/nikki/app.log", command)
        self.assertNotIn("logread", command)
        self.assertEqual("core", result["source"])

    def test_diagnostic_sanitizer_removes_urls_and_credentials(self) -> None:
        raw = (
            "nikki.cfg.url='https://sub.example.test/private-token?x=1'\n"
            "password: super-secret\nAuthorization: Bearer abcdef\n"
            '"api_secret":"control-secret"\n'
        )
        clean = core_module.sanitize_diagnostic_text(
            raw,
            extra_secrets=["super-secret", "abcdef", "control-secret"],
        )

        self.assertNotIn("private-token", clean)
        self.assertNotIn("super-secret", clean)
        self.assertNotIn("abcdef", clean)
        self.assertNotIn("control-secret", clean)
        self.assertIn("[скрыто]", clean)

    def test_apk_failure_diagnostic_names_missing_packages_without_urls(self) -> None:
        raw = (
            "ERROR: unable to select packages:\n"
            "  kmod-nft-tproxy (no such package):\n"
            "    required by: nikki-2026.04.08-r1[kmod-nft-tproxy]\n"
            "repository: https://packages.example.test/private/index.adb\n"
            "__KATO_PACKAGE_EXIT__=1\n"
        )

        diagnostic = core_module.package_manager_failure_diagnostic(raw, "apk")

        self.assertEqual("Репозитории роутера не предоставили пакеты: kmod-nft-tproxy.", diagnostic)
        self.assertNotIn("packages.example.test", diagnostic)

    def test_apk_failure_diagnostic_classifies_world_conflict(self) -> None:
        raw = "ERROR: package-a-1.0 breaks: world[package-a=2.0]\n__KATO_PACKAGE_EXIT__=1"

        diagnostic = core_module.package_manager_failure_diagnostic(raw, "apk")

        self.assertEqual("Установленный набор пакетов конфликтует с новым VPN-модулем.", diagnostic)

    def test_apk_failure_diagnostic_classifies_interrupted_tls_download(self) -> None:
        raw = (
            "wgetSSL error: error:00000001:lib(0)::reason(1)\n"
            "ERROR: wget: exited with error 4\n"
            "WARNING: fetching https://downloads.example.test/packages.adb: unexpected end of file\n"
            "__KATO_PACKAGE_EXIT__=3\n"
        )

        diagnostic = core_module.package_manager_failure_diagnostic(raw, "apk")

        self.assertEqual("Роутер не смог загрузить индекс или пакет из репозитория.", diagnostic)
        self.assertNotIn("downloads.example.test", diagnostic)

    def test_backup_creation_and_exact_deletion_are_separate_operations(self) -> None:
        class BackupSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                return {
                    "проверка созданного backup": "1",
                    "проверка удаляемого backup": "1",
                    "удаление backup": "",
                    "проверка удаления backup": "deleted",
                }.get(label, value)

        created_session = BackupSession(self.spec)
        created = core_module.create_nikki_backup(
            self.spec,
            created_session.fingerprint,
            session_factory=lambda _spec: created_session,
        )
        self.assertEqual("backup", created["operation"])
        self.assertIn("backup Nikki", created_session.labels)

        deleted_session = BackupSession(self.spec)
        deleted = core_module.delete_nikki_backup(
            self.spec,
            deleted_session.fingerprint,
            "20260803-100000-deadbeef",
            session_factory=lambda _spec: deleted_session,
        )
        self.assertEqual("backup_delete", deleted["operation"])
        self.assertIn("/root/katovpn-nikki-backups/20260803-100000-deadbeef", deleted_session.commands["удаление backup"])

    def test_adblock_install_uses_only_targeted_official_packages_and_dry_run(self) -> None:
        class AdblockSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                return {
                    "проверка AdBlock": "memory_kb=524288\nopkg=1\napk=0",
                    "обновление списка пакетов AdBlock": "",
                    "проверка доступности пакетов AdBlock": "adblock=1\nluci-app-adblock=1\nluci-i18n-adblock-ru=1",
                    "проверка установки AdBlock": "__KATO_ADBLOCK_DRYRUN__=0",
                    "установка AdBlock": "",
                    "проверка AdBlock после установки": "adblock=1\nluci-app-adblock=1\nluci-i18n-adblock-ru=1",
                }.get(label, value)

        fake = AdblockSession(self.spec)
        result = core_module.install_adblock(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
        )

        self.assertEqual("adblock_install", result["operation"])
        dry_run = fake.commands["проверка установки AdBlock"]
        install = fake.commands["установка AdBlock"]
        for package in ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru"):
            self.assertIn(package, dry_run)
            self.assertIn(package, install)
        self.assertNotIn("opkg upgrade", "\n".join(fake.commands.values()))

    def test_app_state_can_stage_subscription_without_touching_router(self) -> None:
        state = server_module.AppState()
        state.save_router_session(self.spec, "SHA256:unit-test-router", {"subscription": {"configured": False}})
        state.stage_subscription("https://subscribe.example.test/staged-token")

        public = state.public_router_session()
        self.assertEqual("https://subscribe.example.test/staged-token", public["dashboard"]["subscription"]["url"])
        self.assertTrue(public["dashboard"]["subscription"]["staged"])

    def test_inputs_require_https_subscription(self) -> None:
        with self.assertRaises(SetupError) as raised:
            validate_inputs(
                {
                    "host": "192.168.1.1",
                    "username": "root",
                    "password": "x",
                    "subscription_url": "http://subscribe.example.test/token",
                }
            )
        self.assertEqual("invalid_subscription_url", raised.exception.code)

        update_spec = validate_inputs(
            {
                "host": "192.168.1.1",
                "username": "root",
                "password": "x",
                "subscription_url": "not-used-in-update-mode",
            },
            require_subscription=False,
        )
        self.assertEqual("", update_spec.subscription_url)

    def test_subscription_rejects_redirect_from_https_to_http(self) -> None:
        class Response:
            status_code = 200
            url = "http://subscribe.example.test/tokenized-path"
            content = VALID_PROFILE
            headers = {"content-type": "text/yaml"}

        with self.assertRaises(SetupError) as raised:
            fetch_and_validate_subscription(
                self.spec.subscription_url,
                get=lambda *_args, **_kwargs: Response(),
            )
        self.assertEqual("subscription_insecure_redirect", raised.exception.code)

    def test_official_release_metadata_is_sanitized(self) -> None:
        class Response:
            status_code = 200
            url = "https://api.github.com/repos/nikkinikki-org/OpenWrt-nikki/releases/latest"

            @staticmethod
            def json() -> dict:
                return {
                    "tag_name": "v1.26.0",
                    "published_at": "2026-04-10T07:22:21Z",
                    "assets": [
                        {"name": "nikki_aarch64_cortex-a53-openwrt-24.10.tar.gz"},
                        {"name": "unsafe/name"},
                    ],
                }

        release = fetch_latest_nikki_release(get=lambda *_args, **_kwargs: Response())
        self.assertEqual("available", release["status"])
        self.assertEqual("1.26.0", release["version"])
        self.assertEqual(1, len(release["assets"]))

    def test_official_nikki_package_index_is_sanitized(self) -> None:
        class Response:
            status_code = 200
            url = "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json"

            @staticmethod
            def json() -> dict:
                return {
                    "packages": {
                        "nikki": "2026.04.08-r1",
                        "luci-app-nikki": "1.26.1-r1",
                        "mihomo-meta": "1.19.29",
                        "ignored-package": "secret",
                    }
                }

        result = fetch_latest_nikki_packages(
            "24.10-SNAPSHOT",
            "aarch64_cortex-a53",
            get=lambda *_args, **_kwargs: Response(),
        )
        self.assertEqual("available", result["status"])
        self.assertEqual("1.19.29", result["packages"]["mihomo-meta"])
        self.assertNotIn("ignored-package", result["packages"])

    def test_portable_template_has_working_no_tun_contract_and_no_secrets(self) -> None:
        text = profile_template_path().read_text(encoding="utf-8")
        result = validate_portable_template(text)
        self.assertEqual(0, result["rules"])
        self.assertNotIn("config subscription", text)
        self.assertNotIn("api_secret", text)
        self.assertNotIn("option password", text)
        self.assertIn("option tcp_mode 'redirect'", text)
        self.assertIn("option udp_mode 'tproxy'", text)
        self.assertNotIn("config nameserver", text)
        self.assertNotIn("config nameserver_policy", text)
        self.assertNotIn("223.5.5.5", text)
        self.assertNotIn("option matcher", text)
        self.assertNotIn("⚡️ Авто", text)
        self.assertNotIn("Нидерланды", text)

    def test_ui_exposes_router_control_sections_and_safe_operations(self) -> None:
        html = (TOOL_ROOT / "web" / "index.html").read_text(encoding="utf-8")
        script = (TOOL_ROOT / "web" / "app.js").read_text(encoding="utf-8")
        self.assertIn("logo.png", html)
        self.assertTrue((TOOL_ROOT / "web" / "logo.png").is_file())
        self.assertIn("Настройка роутера", html)
        self.assertIn('id="login-view"', html)
        self.assertIn('data-view="home"', html)
        self.assertIn('data-view="internet"', html)
        self.assertIn('data-view="firmware"', html)
        self.assertIn('data-view="logs"', html)
        self.assertIn("Установленные модули", html)
        self.assertIn("Nikki, Mihomo Core", script)
        self.assertIn("/api/router/setup-vpn", script)
        self.assertIn("/api/router/update-components", script)
        self.assertIn("/api/router/install-adblock", script)
        self.assertIn("/api/router/export-logs", script)
        self.assertNotIn("Ссылка скрыта", script)
        self.assertNotIn("Ядро роутера", script)

    def test_subscription_contract_is_structural_and_does_not_require_country_targets(self) -> None:
        result = validate_subscription_document(VALID_PROFILE)
        self.assertTrue(result["structure_ok"])
        self.assertFalse(result["tun_enabled"])

        server_owned_names = VALID_PROFILE.replace("🇳🇱 Нидерланды".encode("utf-8"), b"Server Route")
        server_owned_names = server_owned_names.replace("⚡️ Авто".encode("utf-8"), b"Automatic")
        self.assertTrue(validate_subscription_document(server_owned_names)["structure_ok"])

        broken = VALID_PROFILE.replace(b"proxy-groups:", b"proxy-groups: invalid\nignored:")
        with self.assertRaises(SetupError) as raised:
            validate_subscription_document(broken)
        self.assertEqual("invalid_subscription", raised.exception.code)

        malformed_documents = (
            b"proxies:\n  - name: route\n    type: direct\nproxy-groups:\n  - type: select\nrules: []\n",
            b"proxies:\n  - name: route\n    type: direct\ndns: []\nrules: []\n",
        )
        for malformed in malformed_documents:
            with self.subTest(document=malformed):
                with self.assertRaises(SetupError) as malformed_error:
                    validate_subscription_document(malformed)
                self.assertEqual("invalid_subscription", malformed_error.exception.code)

    def test_preflight_is_read_only_and_reports_nftables(self) -> None:
        fake = FakePreflightSession(self.spec)
        report = preflight_router(
            self.spec,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            release_fetcher=lambda: {
                "status": "available",
                "tag": "v1.26.0",
                "version": "1.26.0",
                "published_at": "2026-04-10T07:22:21Z",
                "url": "https://github.com/nikkinikki-org/OpenWrt-nikki/releases/latest",
                "assets": ["nikki_aarch64_cortex-a53-openwrt-24.10.tar.gz"],
            },
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "branch": "openwrt-24.10",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
        )
        self.assertTrue(report["compatible"])
        self.assertEqual("firewall4/nftables", report["nikki"]["firewall_backend"])
        self.assertFalse(report["nikki"]["tun"])
        self.assertEqual("TCP redirect + UDP tproxy", report["nikki"]["current_mode"])
        self.assertFalse(report["nikki"]["current_tun"])
        self.assertEqual("compatible_update_available", report["updates"]["nikki"]["status"])
        self.assertTrue(report["updates"]["nikki"]["can_update"])
        self.assertEqual("1.19.20", report["updates"]["mihomo"]["installed"])
        self.assertEqual("1.19.29", report["updates"]["mihomo"]["latest"])
        self.assertTrue(report["updates"]["mihomo"]["can_update"])
        self.assertNotIn("kernel", report["updates"])
        self.assertNotIn("kernel", report["router"])
        self.assertEqual(1, len(report["backups"]))
        self.assertNotIn("backup Nikki", fake.labels)
        self.assertNotIn("импорт настроек Nikki", fake.labels)
        self.assertTrue(fake.closed)

    def test_preflight_blocks_first_official_mihomo_install_when_overlay_is_too_small(self) -> None:
        class LowSpaceUnmanagedCoreSession(FakePreflightSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                value = super().run(command, label=label, timeout=timeout, check=check)
                if "Package: mihomo-meta" in value:
                    return value.split("\n\nPackage: mihomo-meta", 1)[0]
                if value == "4096":
                    return "19712"
                return value

        fake = LowSpaceUnmanagedCoreSession(self.spec)
        report = preflight_router(
            ConnectionSpec(self.spec.host, self.spec.username, self.spec.password, ""),
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: self.fail("subscription must not be fetched"),
            release_fetcher=lambda: {"status": "unavailable", "version": None, "url": None, "assets": []},
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "branch": "openwrt-24.10",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            check_subscription=False,
        )

        core = report["updates"]["mihomo"]
        self.assertTrue(report["compatible"], "configuration itself must remain available")
        self.assertEqual("insufficient_space", core["status"])
        self.assertFalse(core["can_update"])
        self.assertEqual(19712, core["storage"]["available_kb"])
        self.assertGreater(core["storage"]["required_kb"], core["storage"]["available_kb"])

    def test_selected_nikki_and_mihomo_updates_use_official_compatible_packages(self) -> None:
        fake = FakeSession(self.spec)
        result = configure_router(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            verify_setup=inspect_router_setup,
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            update_nikki=True,
            update_mihomo=True,
        )
        self.assertEqual("1.26.1", result["component_updates"]["nikki"])
        self.assertEqual("1.19.29", result["component_updates"]["mihomo"])
        self.assertLess(fake.labels.index("backup Nikki"), fake.labels.index("проверка установки обновлений"))
        self.assertLess(fake.labels.index("проверка установки обновлений"), fake.labels.index("остановка Nikki"))
        self.assertLess(fake.labels.index("остановка Nikki"), fake.labels.index("установка Mihomo Core"))
        self.assertLess(fake.labels.index("установка Mihomo Core"), fake.labels.index("установка Nikki"))
        self.assertLess(fake.labels.index("проверка обновления компонентов"), fake.labels.index("импорт настроек Nikki"))
        self.assertIn("mihomo-meta_1.19.29_aarch64_cortex-a53.ipk", fake.commands["загрузка обновлений"])
        self.assertIn("luci-app-nikki_1.26.1-r1_all.ipk", fake.commands["загрузка обновлений"])
        self.assertIn("запуск Nikki", fake.labels)
        self.assertIn("/etc/init.d/nikki start", fake.commands["запуск Nikki"])
        self.assertIn("command -v netstat", fake.commands["DNS listener"])
        self.assertIn("/proc/net/udp6", fake.commands["DNS listener"])

    def test_clean_install_uses_official_exact_packages_before_configuring_profile(self) -> None:
        class InstallSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                self.labels.append(label)
                self.commands[label] = command
                responses = {
                    "сведения для установки VPN": json.dumps(
                        {"release": {"distribution": "OpenWrt", "version": "24.10.2"}}
                    ),
                    "готовность установки VPN": (
                        "uci=1\nfw4=1\nnft=1\nopkg=1\nmemory_kb=489472\n"
                        "overlay_free_kb=98304\noverlay_writable=1\npackage_arch=aarch64_cortex-a53\n"
                        "dns=1\nhttps=1\nfeed=1"
                    ),
                    "обновление списка пакетов VPN": "",
                    "загрузка VPN-модуля": "",
                    "проверка установки VPN": "__KATO_OPKG_EXIT__=0",
                    "установка VPN-модуля": "",
                    "проверка пакетов VPN": (
                        "mihomo-meta=1.19.29\nnikki=2026.04.08-r1\nluci-app-nikki=1.26.1-r1"
                    ),
                    "проверка файлов VPN": "ready",
                    "очистка установки VPN": "",
                }
                if label in responses:
                    return responses[label]
                return super().run(command, label=label, timeout=timeout, check=check)

        install_session = InstallSession(self.spec)
        configure_session = FakeSession(self.spec)
        sessions = iter((install_session, configure_session))
        result = install_router_vpn(
            self.spec,
            install_session.fingerprint,
            session_factory=lambda _spec: next(sessions),
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
        )

        self.assertEqual("install", result["operation"])
        self.assertTrue(result["packages_installed"])
        self.assertLess(install_session.labels.index("проверка установки VPN"), install_session.labels.index("установка VPN-модуля"))
        self.assertIn("mihomo-meta_1.19.29_aarch64_cortex-a53.ipk", install_session.commands["загрузка VPN-модуля"])
        self.assertIn("luci-app-nikki_1.26.1-r1_all.ipk", install_session.commands["загрузка VPN-модуля"])
        self.assertIn("импорт настроек Nikki", configure_session.labels)

    def test_clean_install_dry_run_failure_does_not_start_package_install(self) -> None:
        class NoSpaceInstallSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                self.labels.append(label)
                self.commands[label] = command
                responses = {
                    "сведения для установки VPN": json.dumps(
                        {"release": {"distribution": "OpenWrt", "version": "24.10.2"}}
                    ),
                    "готовность установки VPN": (
                        "uci=1\nfw4=1\nnft=1\nopkg=1\nmemory_kb=489472\n"
                        "overlay_free_kb=98304\noverlay_writable=1\npackage_arch=aarch64_cortex-a53\n"
                        "dns=1\nhttps=1\nfeed=1"
                    ),
                    "обновление списка пакетов VPN": "",
                    "загрузка VPN-модуля": "",
                    "проверка установки VPN": "Only have 12000kb available on filesystem, pkg needs 20000\n__KATO_OPKG_EXIT__=1",
                    "очистка установки VPN": "",
                }
                if label in responses:
                    return responses[label]
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = NoSpaceInstallSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            install_router_vpn(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
                package_fetcher=lambda _firmware, _arch: {
                    "status": "available",
                    "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                    "packages": {
                        "nikki": "2026.04.08-r1",
                        "luci-app-nikki": "1.26.1-r1",
                        "mihomo-meta": "1.19.29",
                    },
                },
            )

        self.assertEqual("vpn_install_insufficient_space", raised.exception.code)
        self.assertNotIn("установка VPN-модуля", fake.labels)

    def test_clean_install_supports_openwrt_apk_with_official_repository_and_simulation(self) -> None:
        class ApkInstallSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                self.labels.append(label)
                self.commands[label] = command
                responses = {
                    "сведения для установки VPN": json.dumps(
                        {"release": {"distribution": "OpenWrt", "version": "25.12.5"}}
                    ),
                    "готовность установки VPN": (
                        "uci=1\nfw4=1\nnft=1\nopkg=0\napk=1\nmemory_kb=489472\n"
                        "overlay_free_kb=98304\noverlay_writable=1\npackage_arch=aarch64_cortex-a53\n"
                        "dns=1\nhttps=1\nfeed=1"
                    ),
                    "обновление списка пакетов VPN": "",
                    "проверка установки VPN": "__KATO_PACKAGE_EXIT__=0",
                    "установка VPN-модуля": "",
                    "проверка пакетов VPN": (
                        "mihomo-meta=1.19.29\nnikki=2026.04.08-r1\nluci-app-nikki=1.26.1-r1"
                    ),
                    "проверка файлов VPN": "ready",
                    "очистка установки VPN": "",
                }
                if label in responses:
                    return responses[label]
                return super().run(command, label=label, timeout=timeout, check=check)

        install_session = ApkInstallSession(self.spec)
        configure_session = FakeSession(self.spec)
        sessions = iter((install_session, configure_session))
        result = install_router_vpn(
            self.spec,
            install_session.fingerprint,
            session_factory=lambda _spec: next(sessions),
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-25.12/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
        )

        self.assertEqual("install", result["operation"])
        self.assertNotIn("загрузка VPN-модуля", install_session.labels)
        self.assertIn("apk add --simulate --allow-untrusted --no-cache -X", install_session.commands["проверка установки VPN"])
        self.assertIn("/packages.adb", install_session.commands["проверка установки VPN"])
        self.assertIn("mihomo-meta nikki luci-app-nikki", install_session.commands["установка VPN-модуля"])
        self.assertNotIn("opkg", install_session.commands["установка VPN-модуля"])

    def test_component_update_supports_apk_and_updates_only_selected_packages(self) -> None:
        class ApkUpdateSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "пакетный менеджер обновления":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "apk"
                if label == "проверка установки обновлений":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "__KATO_PACKAGE_EXIT__=0"
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = ApkUpdateSession(self.spec)
        result = core_module.update_router_components(
            self.spec,
            fake.fingerprint,
            update_nikki=True,
            update_mihomo=False,
            session_factory=lambda _spec: fake,
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
        )

        self.assertEqual("1.26.1", result["component_updates"]["nikki"])
        self.assertIn("apk add --simulate --allow-untrusted --no-cache -X", fake.commands["проверка установки обновлений"])
        self.assertIn("nikki luci-app-nikki", fake.commands["установка Nikki"])
        self.assertNotIn("mihomo-meta", fake.commands["установка Nikki"])

    def test_component_update_refuses_a_non_newer_official_version(self) -> None:
        class CurrentCoreSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "пакеты обновления":
                    self.labels.append(label)
                    self.commands[label] = command
                    return (
                        "Package: nikki\nVersion: 2026.04.08-r1\nArchitecture: aarch64_cortex-a53\n\n"
                        "Package: luci-app-nikki\nVersion: 1.26.1-r1\nArchitecture: all\n\n"
                        "Package: mihomo-meta\nVersion: 1.19.29\nArchitecture: aarch64_cortex-a53"
                    )
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = CurrentCoreSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            configure_router(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
                package_fetcher=lambda _firmware, _arch: {
                    "status": "available",
                    "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                    "packages": {
                        "nikki": "2026.04.08-r1",
                        "luci-app-nikki": "1.26.1-r1",
                        "mihomo-meta": "1.19.29",
                    },
                },
                update_mihomo=True,
            )

        self.assertEqual("mihomo_update_no_longer_available", raised.exception.code)
        self.assertFalse(any("opkg install" in command for command in fake.commands.values()))

    def test_component_update_dry_run_stops_before_partial_package_install(self) -> None:
        class NoSpaceSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "проверка установки обновлений":
                    self.labels.append(label)
                    self.commands[label] = command
                    return (
                        "Collected errors:\n"
                        " * verify_pkg_installable: Only have 19712kb available on filesystem /overlay, "
                        "pkg mihomo-meta needs 44175\n"
                        "__KATO_OPKG_EXIT__=255"
                    )
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = NoSpaceSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            core_module.update_router_components(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                package_fetcher=lambda _firmware, _arch: {
                    "status": "available",
                    "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                    "packages": {
                        "nikki": "2026.04.08-r1",
                        "luci-app-nikki": "1.26.1-r1",
                        "mihomo-meta": "1.19.29",
                    },
                },
                update_nikki=True,
                update_mihomo=True,
            )

        self.assertEqual("component_update_insufficient_space", raised.exception.code)
        self.assertFalse(raised.exception.details["package_install_started"])
        self.assertIn("проверка установки обновлений", fake.labels)
        self.assertNotIn("остановка Nikki", fake.labels)
        self.assertNotIn("автоматический откат", fake.labels)

    def test_unrecognized_mihomo_package_does_not_trigger_settings_rollback(self) -> None:
        class UnmanagedCoreSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "пакеты обновления":
                    self.labels.append(label)
                    self.commands[label] = command
                    return (
                        "Package: nikki\nVersion: 2025.12.21-r1\nArchitecture: aarch64_cortex-a53\n\n"
                        "Package: luci-app-nikki\nVersion: 1.25.0-r1\nArchitecture: all"
                    )
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = UnmanagedCoreSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            configure_router(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
                package_fetcher=lambda _firmware, _arch: {
                    "status": "available",
                    "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                    "packages": {
                        "nikki": "2026.04.08-r1",
                        "luci-app-nikki": "1.26.1-r1",
                        "mihomo-meta": "1.19.29",
                    },
                },
                update_mihomo=True,
            )

        self.assertEqual("mihomo_update_no_longer_available", raised.exception.code)
        self.assertNotIn("автоматический откат", fake.labels)
        self.assertNotIn("установка обновлений", fake.labels)
        self.assertFalse(raised.exception.details.get("rolled_back", False))

    def test_unmanaged_mihomo_can_be_adopted_as_official_meta_package(self) -> None:
        class UnmanagedCoreSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "пакеты обновления":
                    self.labels.append(label)
                    self.commands[label] = command
                    return (
                        "Package: nikki\nVersion: 2025.12.21-r1\nArchitecture: aarch64_cortex-a53\n\n"
                        "Package: luci-app-nikki\nVersion: 1.25.0-r1\nArchitecture: all"
                    )
                if label == "версия Mihomo перед обновлением":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "Mihomo Meta v1.19.20 linux arm64"
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = UnmanagedCoreSession(self.spec)
        result = configure_router(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            update_mihomo=True,
        )

        self.assertEqual("1.19.29", result["component_updates"]["mihomo"])
        self.assertIn("mihomo-meta_1.19.29_aarch64_cortex-a53.ipk", fake.commands["загрузка обновлений"])

    def test_update_only_mode_does_not_import_or_replace_the_profile(self) -> None:
        self.assertTrue(
            hasattr(core_module, "update_router_components"),
            "core must expose a component-only update operation",
        )
        fake = FakeSession(self.spec)
        result = core_module.update_router_components(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            update_nikki=True,
            update_mihomo=True,
        )

        self.assertEqual("update", result["operation"])
        self.assertNotIn("импорт настроек Nikki", fake.labels)
        self.assertIn("запуск Nikki после обновления", fake.labels)

    def test_update_only_starts_a_service_that_was_stopped_for_package_install(self) -> None:
        fake = FakeSession(self.spec)
        core_module.update_router_components(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            update_nikki=True,
            update_mihomo=True,
        )

        self.assertIn("запуск Nikki после обновления", fake.labels)
        command = fake.commands["запуск Nikki после обновления"]
        self.assertIn("/etc/init.d/nikki start", command)
        self.assertNotIn("restart", command)

    def test_preflight_does_not_check_or_block_on_linux_kernel_version(self) -> None:
        fake = FakePreflightSession(self.spec)
        fake.kernel_version = "4.4.0"
        report = preflight_router(
            self.spec,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            release_fetcher=lambda: {"status": "unavailable", "version": None, "url": "https://github.com/nikkinikki-org/OpenWrt-nikki/releases/latest", "assets": []},
            package_fetcher=lambda _firmware, _arch: {"status": "unavailable", "url": None, "packages": {}},
        )
        self.assertTrue(report["compatible"])
        self.assertNotIn("kernel", report["router"])
        self.assertNotIn("kernel", report["updates"])

    def test_update_preflight_does_not_fetch_or_require_a_subscription(self) -> None:
        fake = FakePreflightSession(self.spec)
        report = preflight_router(
            ConnectionSpec(self.spec.host, self.spec.username, self.spec.password, ""),
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: self.fail("subscription must not be fetched in update mode"),
            release_fetcher=lambda: {"status": "available", "version": "1.26.1", "url": "https://github.com/nikkinikki-org/OpenWrt-nikki/releases/latest", "assets": []},
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "url": "https://nikkinikki.pages.dev/openwrt-24.10/aarch64_cortex-a53/nikki/index.json",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
            check_subscription=False,
        )

        self.assertTrue(report["subscription"]["skipped"])
        self.assertTrue(report["compatible"])

    def test_lifecycle_stops_server_after_last_browser_session_closes(self) -> None:
        shutdown_called = threading.Event()

        class FakeServer:
            def shutdown(self) -> None:
                shutdown_called.set()

        state = server_module.AppState(
            client_exit_grace_seconds=0.04,
            startup_timeout_seconds=5,
            lifecycle_poll_seconds=0.005,
        )
        state.server = FakeServer()
        state.start_lifecycle_monitor()
        state.client_connected("browser-one")
        state.client_disconnected("browser-one")

        self.assertTrue(shutdown_called.wait(0.5), "server did not stop after the last tab closed")

    def test_lifecycle_survives_page_reload_during_disconnect_grace(self) -> None:
        shutdown_called = threading.Event()

        class FakeServer:
            def shutdown(self) -> None:
                shutdown_called.set()

        state = server_module.AppState(
            client_exit_grace_seconds=0.08,
            startup_timeout_seconds=5,
            lifecycle_poll_seconds=0.005,
        )
        state.server = FakeServer()
        state.start_lifecycle_monitor()
        state.client_connected("old-page")
        state.client_disconnected("old-page")
        time.sleep(0.03)
        state.client_connected("reloaded-page")
        time.sleep(0.09)

        self.assertFalse(shutdown_called.is_set(), "normal page reload stopped the executable")
        state.client_disconnected("reloaded-page")
        self.assertTrue(shutdown_called.wait(0.5))

    def test_lifecycle_waits_for_router_job_before_stopping(self) -> None:
        shutdown_called = threading.Event()

        class FakeServer:
            def shutdown(self) -> None:
                shutdown_called.set()

        state = server_module.AppState(
            client_exit_grace_seconds=0.03,
            startup_timeout_seconds=5,
            lifecycle_poll_seconds=0.005,
        )
        state.server = FakeServer()
        state.start_lifecycle_monitor()
        job = state.create_job()
        job.status = "running"
        state.client_connected("browser-one")
        state.client_disconnected("browser-one")
        time.sleep(0.08)

        self.assertFalse(shutdown_called.is_set(), "running router operation was interrupted")
        job.status = "success"
        self.assertTrue(shutdown_called.wait(0.5), "server did not stop after the router operation finished")

    def test_lifecycle_stops_when_browser_never_connects(self) -> None:
        shutdown_called = threading.Event()

        class FakeServer:
            def shutdown(self) -> None:
                shutdown_called.set()

        state = server_module.AppState(
            client_exit_grace_seconds=0.03,
            startup_timeout_seconds=0.04,
            lifecycle_poll_seconds=0.005,
        )
        state.server = FakeServer()
        state.start_lifecycle_monitor()

        self.assertTrue(shutdown_called.wait(0.5), "abandoned launch left the executable running")

    def test_web_client_opens_and_closes_a_persistent_browser_session(self) -> None:
        script = (TOOL_ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("/api/session/stream", script)
        self.assertIn("/api/session/close", script)
        self.assertIn('window.addEventListener("pagehide"', script)
        self.assertIn("window.sessionStorage", script)

    def test_local_api_exits_after_browser_session_disconnects(self) -> None:
        httpd = None
        thread = None
        stream = None
        try:
            httpd, url = server_module.run_server(open_browser=False)
            httpd.app_state.client_exit_grace_seconds = 0.04
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            parsed = urllib.parse.urlsplit(url)
            token = urllib.parse.parse_qs(parsed.query)["token"][0]
            origin = f"http://{parsed.netloc}"
            client_id = "browser-session-integration"
            request = urllib.request.Request(
                origin + f"/api/session/stream?client_id={client_id}",
                headers={"X-Kato-Token": token, "Origin": origin},
            )
            stream = urllib.request.urlopen(request, timeout=5)
            self.assertIn(b'"connected"', stream.readline())
            close_request = urllib.request.Request(
                origin + "/api/session/close",
                data=json.dumps({"client_id": client_id}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Kato-Token": token,
                    "Origin": origin,
                },
                method="POST",
            )
            with urllib.request.urlopen(close_request, timeout=5) as response:
                self.assertEqual("closed", json.loads(response.read().decode("utf-8"))["status"])
            stream.close()
            stream = None
            thread.join(timeout=1)

            self.assertFalse(thread.is_alive(), "serve_forever remained active after the last tab closed")
        finally:
            if stream is not None:
                stream.close()
            if httpd is not None:
                if thread is not None and thread.is_alive():
                    httpd.shutdown()
                httpd.server_close()
            if thread is not None:
                thread.join(timeout=2)

    def test_local_api_runs_update_only_job_without_subscription(self) -> None:
        original_preflight = server_module.preflight_router
        original_update = server_module.update_router_components
        captured: dict[str, object] = {}

        def fake_preflight(spec: ConnectionSpec, *, check_subscription: bool = True) -> dict:
            captured["preflight_subscription"] = spec.subscription_url
            captured["check_subscription"] = check_subscription
            return {
                "fingerprint": "SHA256:test-api-router",
                "compatible": True,
                "updates": {
                    "nikki": {"can_update": True},
                    "mihomo": {"can_update": True},
                },
            }

        def fake_update(spec: ConnectionSpec, fingerprint: str, **kwargs: object) -> dict:
            captured["update_subscription"] = spec.subscription_url
            captured["fingerprint"] = fingerprint
            captured["update_nikki"] = kwargs.get("update_nikki")
            return {
                "status": "success",
                "operation": "update",
                "backup_path": "/root/katovpn-nikki-backups/test",
                "component_updates": {"nikki": "1.26.1", "mihomo": None},
                "profile_changed": False,
            }

        server_module.preflight_router = fake_preflight
        server_module.update_router_components = fake_update
        httpd = None
        thread = None
        try:
            httpd, url = server_module.run_server(open_browser=False)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            parsed = urllib.parse.urlsplit(url)
            token = urllib.parse.parse_qs(parsed.query)["token"][0]
            origin = f"http://{parsed.netloc}"

            def post(path: str, payload: dict) -> dict:
                request = urllib.request.Request(
                    origin + path,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-Kato-Token": token,
                        "Origin": origin,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))

            connection = {
                "mode": "update",
                "host": "192.0.2.1",
                "port": 22,
                "username": "root",
                "password": "test-only",
                "subscription_url": "",
            }
            preflight = post("/api/preflight", connection)
            started = post(
                "/api/update-components",
                {
                    **connection,
                    "confirmed": True,
                    "preflight_id": preflight["preflight_id"],
                    "fingerprint": preflight["report"]["fingerprint"],
                    "update_nikki": True,
                    "update_mihomo": False,
                },
            )

            deadline = time.time() + 3
            job = None
            while time.time() < deadline:
                request = urllib.request.Request(
                    origin + f"/api/jobs/{started['job_id']}",
                    headers={"X-Kato-Token": token, "Origin": origin},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    job = json.loads(response.read().decode("utf-8"))["job"]
                if job["status"] != "running":
                    break
                time.sleep(0.02)

            self.assertEqual("success", job["status"])
            self.assertEqual("update", job["result"]["operation"])
            self.assertEqual("", captured["preflight_subscription"])
            self.assertEqual("", captured["update_subscription"])
            self.assertFalse(captured["check_subscription"])
        finally:
            server_module.preflight_router = original_preflight
            server_module.update_router_components = original_update
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
            if thread is not None:
                thread.join(timeout=2)

    def test_configure_uploads_url_without_putting_it_in_template(self) -> None:
        fake = FakeSession(self.spec)
        result = configure_router(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            verify_setup=inspect_router_setup,
        )
        self.assertEqual("success", result["status"])
        self.assertEqual(PROFILE_NAME, result["profile_name"])
        self.assertEqual(USER_AGENT, result["user_agent"])
        self.assertEqual("ready", result["setup"]["state"])
        self.assertEqual(self.spec.subscription_url.encode(), fake.writes["/tmp/kato-subscription-url"])
        self.assertNotIn(self.spec.subscription_url.encode(), fake.writes["/tmp/kato-nikki-profile.uci"])
        self.assertNotIn("автоматический откат", fake.labels)

    def test_configure_uses_mihomo_runtime_validation_when_available(self) -> None:
        fake = FakeSession(self.spec)

        configure_router(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            verify_setup=inspect_router_setup,
        )

        command = fake.commands["проверка конфигурации Mihomo"]
        self.assertIn('"$bin" -t -f /etc/nikki/run/config.yaml', command)
        self.assertIn("/usr/libexec/mihomo /usr/bin/mihomo", command)

    def test_invalid_mihomo_runtime_configuration_rolls_back(self) -> None:
        class InvalidRuntimeSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "проверка конфигурации Mihomo":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "invalid"
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = InvalidRuntimeSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            configure_router(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
                verify_setup=inspect_router_setup,
            )

        self.assertEqual("mihomo_runtime_validation", raised.exception.code)
        self.assertTrue(raised.exception.details["rolled_back"])

    def test_final_setup_assessment_failure_is_inside_configuration_rollback(self) -> None:
        class DriftedAssessmentSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "состояние автоматической настройки":
                    self.labels.append(label)
                    self.commands[label] = command
                    return READY_SETUP_FLAGS.replace("proxy_contract=1", "proxy_contract=0")
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = DriftedAssessmentSession(self.spec)

        def require_ready(session: FakeSession) -> dict:
            assessment = inspect_router_setup(session)
            if assessment["state"] != "ready":
                raise SetupError("setup_verification_failed", "Итоговое состояние не подтверждено.")
            return assessment

        with self.assertRaises(SetupError) as raised:
            configure_router(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
                verify_setup=require_ready,
            )

        self.assertEqual("setup_verification_failed", raised.exception.code)
        self.assertTrue(raised.exception.details["rolled_back"])

    def test_existing_subscription_url_is_replaced_in_place_without_package_updates(self) -> None:
        class ReplaceSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "active Nikki subscription":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "cfg123abc"
                if label == "subscription download result":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "1"
                if label == "active profile after subscription change":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "subscription:cfg123abc"
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = ReplaceSession(self.spec)
        result = core_module.replace_router_subscription(
            self.spec,
            fake.fingerprint,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
        )

        self.assertEqual("subscription", result["operation"])
        self.assertEqual("cfg123abc", result["subscription_id"])
        self.assertFalse(result["components_changed"])
        self.assertEqual(self.spec.subscription_url.encode(), fake.writes["/tmp/kato-subscription-url"])
        self.assertFalse(any(self.spec.subscription_url in command for command in fake.commands.values()))
        self.assertFalse(any("uci add nikki subscription" in command for command in fake.commands.values()))
        self.assertFalse(any("opkg " in command or "apk " in command for command in fake.commands.values()))
        self.assertIn("refresh subscription", fake.labels)
        self.assertIn("reload Nikki profile", fake.labels)

    def test_failed_subscription_refresh_rolls_back_the_previous_configuration(self) -> None:
        class FailedReplaceSession(FakeSession):
            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                if label == "active Nikki subscription":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "cfg123abc"
                if label == "subscription download result":
                    self.labels.append(label)
                    self.commands[label] = command
                    return "0"
                return super().run(command, label=label, timeout=timeout, check=check)

        fake = FailedReplaceSession(self.spec)
        with self.assertRaises(SetupError) as raised:
            core_module.replace_router_subscription(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            )

        self.assertEqual("subscription_refresh_failed", raised.exception.code)
        self.assertTrue(raised.exception.details["rolled_back"])
        self.assertIn("автоматический откат", fake.labels)

    def test_failed_verification_triggers_rollback(self) -> None:
        fake = FakeSession(self.spec, fail_dns=True)
        with self.assertRaises(SetupError) as raised:
            configure_router(
                self.spec,
                fake.fingerprint,
                session_factory=lambda _spec: fake,
                subscription_fetcher=lambda _url: validate_subscription_document(VALID_PROFILE),
            )
        self.assertEqual("dns_verification", raised.exception.code)
        self.assertTrue(raised.exception.details["rolled_back"])
        self.assertIn("автоматический откат", fake.labels)

    def test_backup_id_rejects_path_traversal(self) -> None:
        with self.assertRaises(SetupError) as raised:
            validate_backup_id("../../etc/config/nikki")
        self.assertEqual("invalid_backup_id", raised.exception.code)

    def test_manual_restore_creates_safety_backup_and_verifies_runtime(self) -> None:
        fake = FakeSession(self.spec)
        result = restore_router_backup(
            self.spec,
            fake.fingerprint,
            "20260803-100000-deadbeef",
            session_factory=lambda _spec: fake,
        )
        self.assertEqual("restore", result["operation"])
        self.assertTrue(result["safety_backup_path"].startswith("/root/katovpn-nikki-backups/"))
        self.assertIn("backup Nikki", fake.labels)
        self.assertIn("восстановление backup", fake.labels)
        self.assertNotIn("автоматический откат", fake.labels)
        restore_command = fake.commands["восстановление backup"]
        self.assertIn("/etc/init.d/nikki start", restore_command)
        self.assertNotIn("restart", restore_command)

    def test_failed_manual_restore_verification_returns_to_safety_backup(self) -> None:
        fake = FakeSession(self.spec, fail_restore_compare=True)
        with self.assertRaises(SetupError) as raised:
            restore_router_backup(
                self.spec,
                fake.fingerprint,
                "20260803-100000-deadbeef",
                session_factory=lambda _spec: fake,
            )
        self.assertEqual("restore_verification", raised.exception.code)
        self.assertTrue(raised.exception.details["rolled_back"])
        self.assertIn("автоматический откат", fake.labels)


if __name__ == "__main__":
    unittest.main()
