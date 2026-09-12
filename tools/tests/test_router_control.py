from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1] / "nikki-router-setup"
sys.path.insert(0, str(TOOL_ROOT))

from katovpn_router_setup.control import (  # noqa: E402
    build_install_plan,
    fetch_subscription_summary,
    inspect_router,
    mask_subscription_url,
    parse_public_ip_info,
    summarize_subscription_document,
)
from katovpn_router_setup.core import ConnectionSpec, SetupError  # noqa: E402
import katovpn_router_setup.control as control_module  # noqa: E402
import katovpn_router_setup.server as server_module  # noqa: E402
from katovpn_router_setup.server import AppState  # noqa: E402


class FakeControlSession:
    def __init__(self, _spec: ConnectionSpec, **overrides: object):
        self.fingerprint = "SHA256:control-test-router"
        self.closed = False
        self.overrides = overrides

    def connect(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def run(self, _command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
        del timeout, check
        values = {
            "control-board": json.dumps(
                {
                    "kernel": self.overrides.get("kernel", "6.6.119"),
                    "hostname": "kato-router",
                    "model": "Kato Test Router",
                    "board_name": "kato,test-router",
                    "release": {
                        "distribution": "OpenWrt",
                        "version": self.overrides.get("firmware", "24.10.2"),
                        "description": "OpenWrt 24.10.2",
                    },
                }
            ),
            "control-capacity": "\n".join(
                [
                    "uci=1",
                    "fw4=1",
                    "nft=1",
                    f"opkg={self.overrides.get('opkg', 1)}",
                    f"apk={self.overrides.get('apk', 0)}",
                    f"package_arch={self.overrides.get('package_arch', 'aarch64_cortex-a53')}",
                    "luci=1",
                    f"nikki={self.overrides.get('nikki_init', 1)}",
                    f"memory_kb={self.overrides.get('memory_kb', 512 * 1024)}",
                    f"flash_kb={self.overrides.get('flash_kb', 256 * 1024)}",
                    f"overlay_free_kb={self.overrides.get('overlay_free_kb', 96 * 1024)}",
                    f"overlay_writable={self.overrides.get('overlay_writable', 1)}",
                ]
            ),
            "control-internet": "dns=1\nhttps=1\nfeed=1\nclock=1",
            "control-public-ip": json.dumps(
                {
                    "ip": "203.0.113.42",
                    "city": "Moscow",
                    "region": "Moscow",
                    "country_code": "RU",
                    "country_name": "Russia",
                    "org": "Example ISP",
                }
            ),
            "control-packages": (
                "Package: nikki\nVersion: 2026.04.08-r1\nArchitecture: aarch64_cortex-a53\n\n"
                "Package: luci-app-nikki\nVersion: 1.26.1-r1\nArchitecture: all\n\n"
                "Package: mihomo-meta\nVersion: 1.19.29\nArchitecture: aarch64_cortex-a53"
            ),
            "control-package-nikki": (
                "" if self.overrides.get("missing_nikki") else
                "Package: nikki\nVersion: 2026.04.08-r1\nArchitecture: aarch64_cortex-a53"
            ),
            "control-package-luci-app-nikki": (
                "" if self.overrides.get("missing_nikki") else
                "Package: luci-app-nikki\nVersion: 1.26.1-r1\nArchitecture: all"
            ),
            "control-package-mihomo-meta": (
                "" if self.overrides.get("unmanaged_mihomo") else
                "Package: mihomo-meta\nVersion: 1.19.29\nArchitecture: aarch64_cortex-a53"
            ),
            "control-package-mihomo-alpha": "",
            "control-package-mihomo": "",
            "control-mihomo-runtime": str(
                self.overrides.get("mihomo_runtime", "Mihomo Meta v1.19.29 linux arm64")
            ),
            "control-nikki": "status=running\nprofile=subscription:cfg123\ntcp=redirect\nudp=tproxy",
            "control-subscription": str(
                self.overrides.get(
                    "subscription_raw",
                    "id=cfg123\nname=KatoVPN\n"
                    "url=https://subscribe.example.test/private-token\n"
                    "user_agent=katorouter-ru\n"
                    "expire=2099-12-31 23:59:59\nsuccess=1\nupdate=2026-08-06 10:00:00",
                )
            ),
            "control-lan": (
                "ipaddr=192.168.11.1\nnetmask=255.255.255.0\nproto=static\nrollback=1\n"
                "uid=0\npasswd=1\nshadow=1\n"
                f"wifi_sae={self.overrides.get('wifi_sae', 1)}\n"
            ),
            "control-wifi": json.dumps(
                {
                    "radio0": {
                        "up": True,
                        "config": {"channel": "36", "band": "5g", "country": "RU"},
                        "interfaces": [
                            {
                                "section": "default_radio0",
                                "config": {
                                    "mode": "ap",
                                    "ssid": "Kato Home",
                                    "encryption": "sae-mixed",
                                    "key": "fixture-current-psk-must-not-escape",
                                    "network": ["lan"],
                                },
                            }
                        ],
                    },
                    "radio1": {
                        "up": False,
                        "config": {"channel": "auto", "band": "2g", "country": "CN"},
                        "interfaces": [],
                    },
                }
            ),
            "control-backups": "20260803-100000-deadbeef\t1785740400\t640\t1",
        }
        return str(values.get(label, ""))


class RouterControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ConnectionSpec("192.168.11.1", "root", "secret", "", 22)

    def inspect(self, **overrides: object) -> dict:
        subscription_result = overrides.pop(
            "subscription_result",
            {
                "servers": 3,
                "providers": 0,
                "locations": 2,
                "expires_at": "2099-12-31T23:59:59",
            },
        )
        fake = FakeControlSession(self.spec, **overrides)
        return inspect_router(
            self.spec,
            session_factory=lambda _spec: fake,
            subscription_fetcher=lambda _url: dict(subscription_result),
            package_fetcher=lambda _firmware, _arch: {
                "status": "available",
                "branch": "openwrt-24.10",
                "packages": {
                    "nikki": "2026.04.08-r1",
                    "luci-app-nikki": "1.26.1-r1",
                    "mihomo-meta": "1.19.29",
                },
            },
        )

    def test_dashboard_reports_router_public_ip_wifi_and_active_subscription(self) -> None:
        report = self.inspect()

        self.assertTrue(report["connected"])
        self.assertTrue(report["internet"]["online"])
        self.assertEqual("Kato Home", report["wifi"][0]["ssid"])
        self.assertEqual("radio0", report["wifi"][0]["radio"])
        self.assertEqual("RU", report["wifi"][0]["country"])
        self.assertNotIn("key", report["wifi"][0])
        self.assertEqual(
            [
                {"name": "radio0", "band": "5g", "country": "RU", "allowed_countries": ["RU", "CN"], "up": True},
                {"name": "radio1", "band": "2g", "country": "CN", "allowed_countries": ["RU", "CN"], "up": False},
            ],
            report["wifi_radios"],
        )
        self.assertNotIn("fixture-current-psk-must-not-escape", json.dumps(report, ensure_ascii=False))
        self.assertEqual(3, report["subscription"]["servers"])
        self.assertEqual(2, report["subscription"]["locations"])
        self.assertEqual("https://subscribe.example.test/private-token", report["subscription"]["url"])
        self.assertEqual("active", report["subscription"]["state"])
        self.assertEqual("2099-12-31T23:59:59", report["subscription"]["expires_at"])
        self.assertEqual("203.0.113.42", report["public_ip"]["ip"])
        self.assertEqual("🇷🇺", report["public_ip"]["flag"])
        self.assertEqual("Example ISP", report["public_ip"]["provider"])
        self.assertEqual("192.168.11.1", report["lan"]["ipaddr"])

    def test_public_ip_parser_rejects_untrusted_values_without_breaking_dashboard(self) -> None:
        parsed = parse_public_ip_info('{"ip":"not-an-ip","country_code":"RU","org":"Example"}')
        self.assertFalse(parsed["available"])
        self.assertIsNone(parsed["ip"])

    def test_public_ip_lookup_has_https_fallbacks_and_parses_their_provider_fields(self) -> None:
        source = (TOOL_ROOT / "katovpn_router_setup" / "control.py").read_text(encoding="utf-8")
        self.assertIn("https://ipapi.co/json/", source)
        self.assertIn("https://ipwho.is/", source)
        self.assertIn("https://ifconfig.co/json", source)

        ipwho = parse_public_ip_info(
            json.dumps(
                {
                    "ip": "203.0.113.43",
                    "city": "Moscow",
                    "region": "Moscow",
                    "country_code": "RU",
                    "country": "Russia",
                    "connection": {"isp": "Fallback ISP"},
                }
            )
        )
        ifconfig = parse_public_ip_info(
            json.dumps(
                {
                    "ip": "203.0.113.44",
                    "city": "Moscow",
                    "region_name": "Moscow",
                    "country_iso": "RU",
                    "country": "Russia",
                    "asn_org": "Second ISP",
                }
            )
        )

        self.assertEqual("Fallback ISP", ipwho["provider"])
        self.assertEqual("Second ISP", ifconfig["provider"])
        self.assertEqual("RU", ifconfig["country_code"])
        self.assertEqual("Moscow", ifconfig["region"])

    def test_subscription_expiry_uses_standard_userinfo_header(self) -> None:
        class Response:
            status_code = 200
            url = "https://subscribe.example.test/token"
            content = b"proxies: []\n"
            headers = {"subscription-userinfo": "upload=0; download=1; total=2; expire=4102444800"}

        summary = fetch_subscription_summary(Response.url, get=lambda *_args, **_kwargs: Response())

        self.assertEqual(4102444800, summary["expiry_epoch"])
        self.assertTrue(summary["expires_at"].startswith("2100-01-01"))

    def test_fresh_subscription_link_overrides_stale_nikki_failure_and_epoch(self) -> None:
        report = self.inspect(
            subscription_raw=(
                "id=cfg123\nname=KatoVPN\nurl=https://subscribe.example.test/private-token\n"
                "user_agent=katorouter-ru\nexpire=1970-01-01 00:00:00\n"
                "success=0\nupdate=2026-08-06 10:00:00"
            ),
            subscription_result={
                "servers": 23,
                "locations": 14,
                "expiry_epoch": 4102444800,
                "expires_at": "2100-01-01T00:00:00+00:00",
            },
        )

        self.assertEqual("active", report["subscription"]["state"])
        self.assertEqual("live_link", report["subscription"]["source"])
        self.assertEqual("2100-01-01T00:00:00+00:00", report["subscription"]["expires_at"])

    def test_zero_or_epoch_expiry_is_treated_as_missing_when_live_link_works(self) -> None:
        report = self.inspect(
            subscription_raw=(
                "id=cfg123\nname=KatoVPN\nurl=https://subscribe.example.test/private-token\n"
                "expire=0\nsuccess=0\nupdate=2026-08-06 10:00:00"
            ),
            subscription_result={"servers": 23, "locations": 14},
        )

        self.assertEqual("active", report["subscription"]["state"])
        self.assertIsNone(report["subscription"]["expires_at"])

    def test_successful_live_link_without_expiry_does_not_reuse_stale_cached_date(self) -> None:
        report = self.inspect(
            subscription_raw=(
                "id=cfg123\nname=KatoVPN\nurl=https://subscribe.example.test/private-token\n"
                "expire=2099-12-31 23:59:59\nsuccess=1\nupdate=2026-08-06 10:00:00"
            ),
            subscription_result={"servers": 23, "locations": 14},
        )

        self.assertEqual("active", report["subscription"]["state"])
        self.assertEqual("live_link", report["subscription"]["source"])
        self.assertIsNone(report["subscription"]["expires_at"])

    def test_usable_memory_threshold_is_200_mib_and_ignores_marketed_flash_capacity(self) -> None:
        report = self.inspect(memory_kb=228 * 1024, flash_kb=69 * 1024, overlay_free_kb=9 * 1024, kernel="4.4.0")

        self.assertTrue(report["compatibility"]["ready"])
        self.assertEqual(256, report["router"]["memory_mb"])
        self.assertEqual(228, report["router"]["usable_memory_mb"])
        visible_codes = {item["code"] for item in report["compatibility"]["checks"]}
        self.assertIn("memory", visible_codes)
        self.assertNotIn("package_manager", visible_codes)
        self.assertNotIn("kernel", visible_codes)
        self.assertNotIn("flash", visible_codes)
        self.assertNotIn("overlay", visible_codes)
        self.assertNotIn("overlay_writable", visible_codes)

    def test_reserved_memory_is_presented_as_the_physical_router_class(self) -> None:
        report = self.inspect(memory_kb=478 * 1024)

        self.assertEqual(512, report["router"]["memory_mb"])
        self.assertEqual(478, report["router"]["usable_memory_mb"])
        visible_codes = {item["code"] for item in report["compatibility"]["checks"]}
        self.assertNotIn("memory_recommended", visible_codes)

    def test_overlay_writability_blocks_install_without_duplicating_the_visible_internet_check(self) -> None:
        report = self.inspect(
            missing_nikki=True,
            nikki_init=0,
            unmanaged_mihomo=True,
            mihomo_runtime="unknown",
            overlay_writable=0,
        )

        visible_codes = {item["code"] for item in report["compatibility"]["checks"]}
        self.assertNotIn("package_manager", visible_codes)
        self.assertNotIn("overlay_writable", visible_codes)
        self.assertFalse(report["compatibility"]["install_ready"])
        self.assertFalse(report["safety"]["install_enabled"])

    def test_apk_only_openwrt_can_install_the_official_vpn_module(self) -> None:
        report = self.inspect(
            firmware="25.12.5",
            opkg=0,
            apk=1,
            package_arch="aarch64_cortex-a53",
            missing_nikki=True,
            nikki_init=0,
            unmanaged_mihomo=True,
            mihomo_runtime="unknown",
        )

        self.assertEqual("apk", report["router"]["package_manager"])
        self.assertTrue(report["compatibility"]["install_ready"])
        self.assertTrue(report["safety"]["install_enabled"])
        blockers = {item["code"] for item in report["compatibility"]["install_blockers"]}
        self.assertNotIn("package_manager", blockers)
        source = (TOOL_ROOT / "katovpn_router_setup" / "control.py").read_text(encoding="utf-8")
        self.assertIn("DISTRIB_ARCH", source)
        self.assertIn("apk list --installed --manifest", source)

    def test_clean_install_still_checks_free_space_but_not_physical_flash(self) -> None:
        report = self.inspect(
            memory_kb=199 * 1024,
            flash_kb=69 * 1024,
            overlay_free_kb=9 * 1024,
            unmanaged_mihomo=True,
            mihomo_runtime="unknown",
        )

        codes = {item["code"] for item in report["compatibility"]["checks"] if item["status"] == "block"}
        self.assertEqual({"memory", "overlay"}, codes)

    def test_unmanaged_mihomo_runtime_is_reported_as_installed_and_current(self) -> None:
        report = self.inspect(unmanaged_mihomo=True)

        core = report["components"]["mihomo"]
        self.assertTrue(core["installed"])
        self.assertFalse(core["managed"])
        self.assertEqual("1.19.29", core["version"])
        self.assertEqual("current_unmanaged", core["status"])

    def test_mihomo_package_without_a_working_runtime_is_not_reported_as_running(self) -> None:
        report = self.inspect(mihomo_runtime="unknown")

        core = report["components"]["mihomo"]
        self.assertFalse(core["installed"])
        self.assertTrue(core["managed"])
        self.assertEqual("runtime_missing", core["status"])

    def test_install_plan_prefers_feed_and_has_a_pc_fallback_without_blanket_upgrade(self) -> None:
        report = self.inspect()
        primary = build_install_plan(report, pc_packages_available=True)
        report["internet"]["nikki_feed"] = False
        fallback = build_install_plan(report, pc_packages_available=True)

        self.assertEqual("official_feed", primary["method"])
        self.assertEqual("pc_upload", fallback["method"])
        self.assertTrue(primary["dry_run_required"])
        self.assertTrue(primary["hardware_validated"])
        commands = "\n".join(primary["commands"] + fallback["commands"])
        self.assertNotIn("opkg upgrade", commands)
        self.assertNotIn("apk upgrade", commands)
        self.assertIn("mihomo-meta", primary["packages"])
        self.assertIn("luci-app-nikki", primary["packages"])

    def test_wifi_actions_fail_closed_without_sae_mixed_support(self) -> None:
        report = self.inspect(wifi_sae=0)

        self.assertFalse(report["safety"]["wifi_changes_enabled"])
        self.assertFalse(report["safety"]["wifi_create_enabled"])

    def test_subscription_mask_keeps_only_origin(self) -> None:
        masked = mask_subscription_url("https://user.example.test:8443/token/path?secret=yes")
        self.assertEqual("https://user.example.test:8443/…", masked)

    def test_dashboard_exposes_fresh_setup_assessment(self) -> None:
        assessment = {"state": "needs_configuration", "action": "configure",
                      "message": "Нужно настроить роутер для работы с KatoVPN",
                      "warnings": [], "details": {}}
        with patch.object(control_module, "inspect_router_setup", return_value=assessment, create=True) as probe:
            result = self.inspect()
        self.assertEqual(assessment, result.get("setup"))
        self.assertEqual(1, probe.call_count)

    def test_dashboard_does_not_manage_or_probe_adblock(self) -> None:
        report = self.inspect()

        self.assertNotIn("adblock", report["components"])
        self.assertNotIn("adblock_install_enabled", report["safety"])
        source = (TOOL_ROOT / "katovpn_router_setup" / "control.py").read_text(encoding="utf-8")
        self.assertNotIn("control-package-adblock", source)
        self.assertNotIn("control-adblock-available", source)

    def test_router_jobs_are_exclusive_until_previous_operation_finishes(self) -> None:
        state = AppState()
        first = state.create_job()
        with self.assertRaises(SetupError) as raised:
            state.create_job()
        self.assertEqual("router_busy", raised.exception.code)
        first.status = "failed"
        self.assertNotEqual(first.id, state.create_job().id)

    def test_app_state_keeps_one_router_session_in_memory_and_forgets_it(self) -> None:
        state = AppState()
        state.save_router_session(self.spec, "SHA256:control-test-router", {"connected": True})

        saved = state.get_router_session()
        self.assertEqual("secret", saved["spec"].password)
        public = state.public_router_session()
        self.assertNotIn("password", json.dumps(public))
        state.clear_router_session()
        self.assertIsNone(state.get_router_session())

    def test_new_ui_is_a_four_section_router_launcher(self) -> None:
        html = (TOOL_ROOT / "web" / "index.html").read_text(encoding="utf-8")
        css = (TOOL_ROOT / "web" / "styles.css").read_text(encoding="utf-8")
        script = (TOOL_ROOT / "web" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="login-view"', html)
        self.assertIn('id="app-view"', html)
        self.assertIn('data-view="home"', html)
        self.assertIn('data-view="internet"', html)
        self.assertIn('data-view="firmware"', html)
        self.assertIn('data-view="logs"', html)
        self.assertIn("Обслуживание", html)
        self.assertIn('firmware: ["Возможности роутера", "Обслуживание"]', script)
        internet_section = html.split('id="internet-section"', 1)[1].split('id="firmware-section"', 1)[0]
        maintenance_section = html.split('id="firmware-section"', 1)[1].split('id="logs-section"', 1)[0]
        self.assertNotIn('id="support-access"', internet_section)
        self.assertIn('id="support-access"', maintenance_section)
        self.assertLess(maintenance_section.index('id="support-access"'), maintenance_section.index('id="backup-button"'))
        self.assertIn('value="192.168.11.1"', html)
        self.assertIn("Введите данные вашего роутера", html)
        self.assertIn("@katovpnbot", html)
        self.assertIn("@katovpn_help", html)
        self.assertIn("katovpn.app", html)
        self.assertNotIn('name="subscription_url"', html.split('id="login-view"', 1)[1].split('id="app-view"', 1)[0])
        self.assertIn(".username-field, .password-field { grid-column: 1 / -1; }", css)
        self.assertNotIn('id="update-button"', html)
        self.assertIn('title.textContent = "VPN-модуль"', script)
        self.assertIn('sub.textContent = "Nikki, Mihomo Core"', script)
        self.assertIn('startVpnAction', script)
        self.assertIn('"/api/router/setup-vpn"', script)
        self.assertNotIn('["nikki", "mihomo", "adblock"]', script)
        self.assertNotIn('luci: "LuCI"', script)
        self.assertIn("subscription.url", script)
        self.assertNotIn("location_basis", script)
        self.assertNotIn("User-Agent", html)
        self.assertNotIn("WAN / DNS / HTTPS", html)
        self.assertNotIn("Пакетный менеджер", html)
        self.assertIn("Выгрузить логи", html)
        self.assertEqual("0.4.3-preview", server_module.APP_VERSION)
        self.assertNotIn('id="server-count"', html)
        self.assertNotIn('id="location-count"', html)
        self.assertIn("Журнал VPN", html)
        self.assertNotIn('id="log-source"', html)
        self.assertIn("из каждого источника", html)
        self.assertIn('id="router-password-form"', html)
        self.assertIn('item.status !== "block"', script)
        self.assertIn("formatRadioLabel", script)
        self.assertIn("refreshDashboardAfterOperation", script)
        self.assertIn("attempt < 5", script)
        self.assertIn("Разрешить подключение", html)
        self.assertIn("Завершить доступ", html)
        self.assertNotIn("Разрешить поддержку на 1 час", html + script)
        self.assertNotIn("Отключить поддержку", html + script)
        self.assertNotIn('component.installed ? "Актуально"', script)
        self.assertNotIn('component.installed ? "Установлен" : "Установить"', script)
        self.assertEqual(1, script.count('edit.textContent = "Изменить"'))
        self.assertIn('openWifiDialog("edit", network)', script)
        self.assertNotIn('openWifiDialog("change_password"', script)
        self.assertNotIn('action === "change_password"', script)
        self.assertNotIn("Сменить пароль ·", script)
        self.assertIn('id="wifi-ssid-field" class="field"', html)
        self.assertIn('id="wifi-radio-field" class="field"', html)
        self.assertIn('id="wifi-password" type="password" minlength="8" maxlength="63" autocomplete="new-password">', html)
        self.assertIn("Оставьте поле пустым, чтобы сохранить текущий пароль", html)
        self.assertIn('report.wifi_radios || []', script)

    def test_login_api_never_returns_the_router_password(self) -> None:
        original_inspect = server_module.inspect_router
        server_module.inspect_router = lambda _spec: {
            "connected": True,
            "fingerprint": "SHA256:control-test-router",
            "router": {"hostname": "unit-router"},
            "internet": {"online": True},
            "compatibility": {"install_ready": True, "checks": [], "blockers": []},
            "wifi": [],
            "components": {},
            "nikki": {},
            "subscription": {"configured": False},
            "backups": [],
            "official_packages": {},
            "safety": {},
        }
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
                    headers={"Content-Type": "application/json", "X-Kato-Token": token, "Origin": origin},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))

            response = post(
                "/api/router/login",
                {"host": "192.0.2.10", "port": 22, "username": "root", "password": "private-router-password"},
            )
            self.assertNotIn("private-router-password", json.dumps(response))
            self.assertEqual("private-router-password", httpd.app_state.get_router_session()["spec"].password)
            post("/api/router/logout", {})
            self.assertIsNone(httpd.app_state.get_router_session())
        finally:
            server_module.inspect_router = original_inspect
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
            if thread is not None:
                thread.join(timeout=2)

    def test_local_api_starts_clean_vpn_install_with_the_staged_subscription(self) -> None:
        original_inspect = server_module.inspect_router
        original_install = server_module.install_router_vpn
        captured: dict[str, object] = {}
        dashboard = {
            "connected": True,
            "fingerprint": "SHA256:install-api-router",
            "router": {"hostname": "unit-router"},
            "internet": {"online": True},
            "compatibility": {"install_ready": True, "checks": [], "blockers": [], "install_blockers": []},
            "wifi": [],
            "components": {"nikki": {"installed": False}, "mihomo": {"installed": False}},
            "nikki": {},
            "subscription": {"configured": False},
            "backups": [],
            "official_packages": {"status": "available"},
            "safety": {"install_enabled": True},
        }

        def fake_install(spec: ConnectionSpec, fingerprint: str, **_kwargs: object) -> dict:
            captured["subscription_url"] = spec.subscription_url
            captured["fingerprint"] = fingerprint
            return {"status": "success", "operation": "install", "packages_installed": True}

        server_module.inspect_router = lambda _spec: dict(dashboard)
        server_module.install_router_vpn = fake_install
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
                    headers={"Content-Type": "application/json", "X-Kato-Token": token, "Origin": origin},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))

            post("/api/router/login", {"host": "192.0.2.10", "port": 22, "username": "root", "password": "test-only"})
            started = post(
                "/api/router/install-vpn",
                {"confirmed": True, "subscription_url": "https://subscribe.example.test/test-token"},
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
                if job["status"] not in {"queued", "running"}:
                    break
                time.sleep(0.02)

            self.assertEqual("success", job["status"])
            self.assertEqual("https://subscribe.example.test/test-token", captured["subscription_url"])
            self.assertEqual("SHA256:install-api-router", captured["fingerprint"])
        finally:
            server_module.inspect_router = original_inspect
            server_module.install_router_vpn = original_install
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
            if thread is not None:
                thread.join(timeout=2)

    def test_wifi_edit_api_is_allowlisted_and_secret_free(self) -> None:
        original_change_wifi = server_module.change_wifi_configuration
        called: dict[str, object] = {}
        replacement = "fixture-replacement-psk"

        def fake_change_wifi(_spec: ConnectionSpec, _fingerprint: str, **kwargs: object) -> dict:
            called.update(kwargs)
            return {
                "operation": "wifi_edit",
                "section": kwargs["section"],
                "ssid": kwargs["ssid"],
                "radio": kwargs["radio"],
                "country": kwargs["country"],
                "password_changed": bool(kwargs["password"]),
            }

        server_module.change_wifi_configuration = fake_change_wifi
        httpd = None
        thread = None
        try:
            httpd, url = server_module.run_server(open_browser=False)
            httpd.app_state.save_router_session(
                self.spec,
                "SHA256:control-test-router",
                {
                    "safety": {"wifi_changes_enabled": True, "wifi_create_enabled": True},
                    "lan": {"recommended_country": "RU"},
                    "wifi": [{"section": "default_radio0", "radio": "radio0", "ssid": "Kato Home"}],
                    "wifi_radios": [
                        {"name": "radio0", "allowed_countries": ["RU", "CN"]},
                        {"name": "radio1", "allowed_countries": ["RU", "CN"]},
                    ],
                },
            )
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            parsed = urllib.parse.urlsplit(url)
            token = urllib.parse.parse_qs(parsed.query)["token"][0]
            origin = f"http://{parsed.netloc}"

            def post(payload: dict) -> dict:
                request = urllib.request.Request(
                    origin + "/api/router/wifi",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-Kato-Token": token, "Origin": origin},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))

            def get_job(job_id: str) -> dict:
                request = urllib.request.Request(
                    origin + f"/api/jobs/{job_id}",
                    headers={"X-Kato-Token": token, "Origin": origin},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))["job"]

            accepted = post(
                {
                    "confirmed": True,
                    "action": "edit",
                    "section": "default_radio0",
                    "ssid": "Kato Edited",
                    "radio": "radio1",
                    "country": "CN",
                    "password": replacement,
                }
            )
            public_job = {}
            for _ in range(50):
                public_job = get_job(accepted["job_id"])
                if public_job.get("status") in {"done", "failed"}:
                    break
                time.sleep(0.02)

            self.assertEqual("default_radio0", called["section"])
            self.assertEqual("Kato Edited", called["ssid"])
            self.assertEqual("radio1", called["radio"])
            self.assertEqual("CN", called["country"])
            self.assertEqual(replacement, called["password"])
            self.assertNotIn(replacement, json.dumps(accepted, ensure_ascii=False))
            self.assertNotIn(replacement, json.dumps(public_job, ensure_ascii=False))
            self.assertEqual("wifi_edit", public_job["result"]["operation"])

            for rejected_payload, expected_code in (
                ({"confirmed": True, "action": "change_password", "section": "default_radio0", "ssid": "Kato Edited", "radio": "radio1", "country": "CN", "password": ""}, "invalid_wifi_action"),
                ({"confirmed": True, "action": "edit", "section": "unknown_network", "ssid": "Kato Edited", "radio": "radio1", "country": "CN", "password": ""}, "invalid_wifi_section"),
                ({"confirmed": True, "action": "edit", "section": "default_radio0", "ssid": "Kato Edited", "radio": "radio9", "country": "CN", "password": ""}, "invalid_wifi_radio"),
            ):
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    post(rejected_payload)
                error_payload = json.loads(rejected.exception.read().decode("utf-8"))
                self.assertEqual(expected_code, error_payload["error"]["code"])
        finally:
            server_module.change_wifi_configuration = original_change_wifi
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
            if thread is not None:
                thread.join(timeout=2)


class AutomaticSetupApiTests(unittest.TestCase):
    def patched(self, name, **kwargs):
        patcher = patch.object(server_module, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self) -> None:
        self.spec = ConnectionSpec("192.0.2.10", "root", "test-password", "", 22)
        self.fingerprint = "SHA256:setup-api-test"
        self.dashboard = {
            "connected": True, "fingerprint": self.fingerprint,
            "compatibility": {"ready": True, "install_ready": True, "blockers": []},
            "components": {"nikki": {"installed": True}, "mihomo": {"installed": True}},
            "subscription": {"configured": True},
            "setup": {"state": "needs_configuration", "action": "configure", "warnings": []},
        }
        self.probe = self.patched("inspect_router", return_value=self.dashboard)
        self.patched("preflight_router", side_effect=AssertionError("legacy preflight must not run"))
        self.patched("fetch_and_validate_subscription", return_value={"tun_enabled": False})
        self.patched("install_adblock", create=True, side_effect=AssertionError("retired endpoint must not mutate router"))
        self.setup = self.patched("setup_router_vpn", create=True,
            return_value={"status": "success", "operation": "setup"})
        self.httpd, url = server_module.run_server(open_browser=False)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        parsed = urllib.parse.urlsplit(url)
        self.origin = f"http://{parsed.netloc}"
        self.token = urllib.parse.parse_qs(parsed.query)["token"][0]
        self.httpd.app_state.save_router_session(self.spec, self.fingerprint, self.dashboard)

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def post(self, payload=None, *, path="/api/router/setup-vpn", authorized=True):
        body = json.dumps(payload if payload is not None else {
            "confirmed": True, "subscription_url": "https://setup.example.test/d/test-token"}).encode()
        request = urllib.request.Request(self.origin + path,
            data=body if authorized else b"",
            headers={"Content-Type": "application/json", "Origin": self.origin,
                     "X-Kato-Token": self.token if authorized else "invalid"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def get(self, path: str):
        request = urllib.request.Request(
            self.origin + path,
            headers={"Origin": self.origin, "X-Kato-Token": self.token},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.load(response)

    def finished_job(self, job_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            job = self.httpd.app_state.jobs[job_id].public()
            if job["status"] not in {"queued", "running"}:
                return job
            time.sleep(0.01)
        self.fail("setup job did not finish")

    def test_setup_requires_authorization_confirmation_and_router_session(self) -> None:
        self.assertEqual(403, self.post(authorized=False)[0])
        self.assertEqual("confirmation_required", self.post({})[1]["error"]["code"])
        self.httpd.app_state.clear_router_session()
        self.assertEqual("router_session_required", self.post()[1]["error"]["code"])
        self.setup.assert_not_called()

    def test_manual_nikki_uses_automatic_setup_and_refreshes_saved_dashboard(self) -> None:
        code, response = self.post()
        self.assertEqual(202, code)
        job = self.finished_job(response["job_id"])
        self.assertEqual("success", job["status"])
        args = self.setup.call_args.args
        self.assertEqual(self.fingerprint, args[1])
        self.assertEqual("https://setup.example.test/d/test-token", args[0].subscription_url)
        self.assertGreaterEqual(self.probe.call_count, 2)
        self.assertEqual("setup", job["result"]["operation"])
        self.assertNotIn(self.spec.password, json.dumps(job))

    def test_legacy_configure_endpoint_cannot_skip_manual_nikki_normalization(self) -> None:
        code, response = self.post(path="/api/router/configure-subscription")
        self.assertEqual(202, code)
        self.assertEqual("success", self.finished_job(response["job_id"])["status"])
        self.setup.assert_called_once()

    def test_changed_identity_prevents_setup(self) -> None:
        self.probe.return_value = {**self.dashboard, "fingerprint": "SHA256:other-router"}
        code, response = self.post()
        self.assertEqual(202, code)
        job = self.finished_job(response["job_id"])
        self.assertEqual("failed", job["status"])
        self.assertEqual("router_fingerprint_changed", job["error"]["code"])
        self.setup.assert_not_called()
        self.assertIsNone(self.httpd.app_state.get_router_session())

    def test_legacy_stale_missing_components_does_not_stage_over_manual_install(self) -> None:
        stale = {**self.dashboard, "components": {}, "subscription": {"configured": False}}
        self.httpd.app_state.save_router_session(self.spec, self.fingerprint, stale)
        code, response = self.post(path="/api/router/configure-subscription")
        self.assertEqual(202, code)
        self.assertEqual("success", self.finished_job(response["job_id"])["status"])
        self.setup.assert_called_once()

    def test_legacy_staging_cannot_replace_link_during_running_job(self) -> None:
        self.probe.return_value = {**self.dashboard, "components": {}}
        self.httpd.app_state.create_job()
        code, response = self.post(path="/api/router/configure-subscription")
        self.assertEqual(400, code)
        self.assertEqual("router_busy", response["error"]["code"])
        self.assertEqual("", self.httpd.app_state.get_router_session()["staged_subscription_url"])

    def test_setup_failure_is_reported_and_releases_busy_slot(self) -> None:
        self.setup.side_effect = SetupError("setup_verification", "Настройка не завершена.")
        code, response = self.post()
        self.assertEqual(202, code)
        job = self.finished_job(response["job_id"])
        self.assertEqual("setup_verification", job["error"]["code"])
        self.assertNotEqual(response["job_id"], self.httpd.app_state.create_job().id)

    def test_stale_ready_dashboard_cannot_override_fresh_incompatibility(self) -> None:
        self.probe.return_value = {**self.dashboard,
            "compatibility": {"ready": False, "blockers": ["unsupported firmware"]}}
        code, response = self.post()
        self.assertEqual(202, code)
        job = self.finished_job(response["job_id"])
        self.assertEqual("router_incompatible", job["error"]["code"])
        self.setup.assert_not_called()

    def test_retired_adblock_endpoint_is_not_found_and_creates_no_job(self) -> None:
        jobs_before = dict(self.httpd.app_state.jobs)

        code, response = self.post(path="/api/router/install-adblock")
        meta_code, meta = self.get("/api/meta")

        self.assertEqual(404, code)
        self.assertEqual("not_found", response["error"]["code"])
        self.assertEqual(jobs_before, self.httpd.app_state.jobs)
        self.assertEqual(200, meta_code)
        self.assertNotIn("adblock", meta["implemented_modes"])


if __name__ == "__main__":
    unittest.main()
