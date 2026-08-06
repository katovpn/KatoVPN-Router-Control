from __future__ import annotations

import json
import sys
import threading
import unittest
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
from katovpn_router_setup.core import ConnectionSpec  # noqa: E402
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
                    "opkg=1",
                    "apk=0",
                    "luci=1",
                    "nikki=1",
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
            "control-package-nikki": "Package: nikki\nVersion: 2026.04.08-r1\nArchitecture: aarch64_cortex-a53",
            "control-package-luci-app-nikki": "Package: luci-app-nikki\nVersion: 1.26.1-r1\nArchitecture: all",
            "control-package-mihomo-meta": (
                "" if self.overrides.get("unmanaged_mihomo") else
                "Package: mihomo-meta\nVersion: 1.19.29\nArchitecture: aarch64_cortex-a53"
            ),
            "control-package-mihomo-alpha": "",
            "control-package-mihomo": "",
            "control-package-adblock": (
                "Package: adblock\nVersion: 4.4.2-r1\nArchitecture: all"
                if self.overrides.get("adblock_installed") else ""
            ),
            "control-package-luci-app-adblock": (
                "Package: luci-app-adblock\nVersion: 25.300.1\nArchitecture: all"
                if self.overrides.get("adblock_installed") else ""
            ),
            "control-package-luci-i18n-adblock-ru": (
                "Package: luci-i18n-adblock-ru\nVersion: 25.300.1\nArchitecture: all"
                if self.overrides.get("adblock_installed") else ""
            ),
            "control-mihomo-runtime": str(
                self.overrides.get("mihomo_runtime", "Mihomo Meta v1.19.29 linux arm64")
            ),
            "control-nikki": "status=running\nprofile=subscription:cfg123\ntcp=redirect\nudp=tproxy",
            "control-subscription": str(
                self.overrides.get(
                    "subscription_raw",
                    "id=cfg123\nname=KatoVPN\n"
                    "url=https://subscribe.example.test/private-token\n"
                    "user_agent=mihomo KatoVPN-Router/1.0\n"
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
                        "config": {"channel": "36", "band": "5g"},
                        "interfaces": [
                            {
                                "section": "default_radio0",
                                "config": {
                                    "mode": "ap",
                                    "ssid": "Kato Home",
                                    "encryption": "sae-mixed",
                                    "network": ["lan"],
                                },
                            }
                        ],
                    }
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
        self.assertNotIn("key", report["wifi"][0])
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
                "user_agent=mihomo KatoVPN-Router/1.0\nexpire=1970-01-01 00:00:00\n"
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
        visible_codes = {item["code"] for item in report["compatibility"]["checks"]}
        self.assertIn("memory", visible_codes)
        self.assertNotIn("package_manager", visible_codes)
        self.assertNotIn("kernel", visible_codes)
        self.assertNotIn("flash", visible_codes)
        self.assertNotIn("overlay", visible_codes)
        self.assertNotIn("overlay_writable", visible_codes)

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
        self.assertFalse(primary["hardware_validated"])
        commands = "\n".join(primary["commands"] + fallback["commands"])
        self.assertNotIn("opkg upgrade", commands)
        self.assertNotIn("apk upgrade", commands)
        self.assertIn("mihomo-meta", primary["packages"])
        self.assertIn("luci-app-nikki", primary["packages"])

    def test_adblock_is_optional_and_only_eligible_on_512_mib_class_router(self) -> None:
        small = self.inspect(memory_kb=256 * 1024)
        large = self.inspect(memory_kb=512 * 1024)
        installed = self.inspect(memory_kb=512 * 1024, adblock_installed=True)

        self.assertFalse(small["components"]["adblock"]["eligible"])
        self.assertTrue(large["components"]["adblock"]["eligible"])
        self.assertFalse(large["components"]["adblock"]["installed"])
        self.assertTrue(installed["components"]["adblock"]["installed"])

    def test_wifi_actions_fail_closed_without_sae_mixed_support(self) -> None:
        report = self.inspect(wifi_sae=0)

        self.assertFalse(report["safety"]["wifi_changes_enabled"])
        self.assertFalse(report["safety"]["wifi_create_enabled"])

    def test_subscription_mask_keeps_only_origin(self) -> None:
        masked = mask_subscription_url("https://user.example.test:8443/token/path?secret=yes")
        self.assertEqual("https://user.example.test:8443/…", masked)

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
        self.assertIn('value="192.168.11.1"', html)
        self.assertIn("Введите данные вашего роутера", html)
        self.assertIn("@katovpnbot", html)
        self.assertIn("@katovpn_help", html)
        self.assertIn("katovpn.app", html)
        self.assertNotIn('name="subscription_url"', html.split('id="login-view"', 1)[1].split('id="app-view"', 1)[0])
        self.assertIn(".username-field, .password-field { grid-column: 1 / -1; }", css)
        self.assertNotIn('id="update-button"', html)
        self.assertIn('["nikki", "mihomo", "adblock"]', script)
        self.assertIn('setAttribute("data-update-component", key)', script)
        self.assertIn("startUpdate(key)", script)
        self.assertNotIn('luci: "LuCI"', script)
        self.assertIn("subscription.url", script)
        self.assertNotIn("location_basis", script)
        self.assertNotIn("User-Agent", html)
        self.assertNotIn("WAN / DNS / HTTPS", html)
        self.assertNotIn("Пакетный менеджер", html)
        self.assertIn("Выгрузить логи", html)
        self.assertEqual("0.4.2-preview", server_module.APP_VERSION)
        self.assertNotIn('id="server-count"', html)
        self.assertNotIn('id="location-count"', html)
        self.assertIn("Журнал VPN", html)
        self.assertNotIn('id="log-source"', html)
        self.assertIn("из каждого источника", html)
        self.assertIn('id="router-password-form"', html)
        self.assertIn('item.status !== "block"', script)
        self.assertIn("formatRadioLabel", script)

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


if __name__ == "__main__":
    unittest.main()
