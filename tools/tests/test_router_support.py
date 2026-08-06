from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1] / "nikki-router-setup"
sys.path.insert(0, str(TOOL_ROOT))

from katovpn_router_setup.core import ConnectionSpec, SetupError  # noqa: E402
from katovpn_router_setup.server import AppState  # noqa: E402
from katovpn_router_setup.support import (  # noqa: E402
    SupportRelayConfig,
    SupportSessionManager,
    build_support_install_command,
    build_support_remove_command,
    install_temporary_support_key,
    load_support_relay_config,
    validate_support_public_key,
)


SUPPORT_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCVs7hycgxXcXi2pNWzAbhDIgyGzvfL47SsxdHJoki9AYZIl/9+XWlSy89ATHlXpRH7LrBG4/"
    "Zb67nqfHAsX0b1A8+EGjpHIXD65lR5VuBDowGC0c2atQQRbjJOe2S7U7z0XJFkJtrwWsH4ruseMyOmPokACSayAvGrTrebhokoqw== Kato Support"
)


class FakeTimer:
    def __init__(self, _delay: float, callback):
        self.callback = callback
        self.started = False
        self.cancelled = False
        self.daemon = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True


class FakeRelay:
    def __init__(self) -> None:
        self.created_with = ""
        self.revoked: list[tuple[str, str]] = []

    def create_session(self, client_public_key: str, *, duration_seconds: int):
        self.created_with = client_public_key
        self.duration_seconds = duration_seconds
        return {
            "session_id": "session-12345678",
            "code": "KATO-7H2K9M",
            "expires_at": 4102444800,
            "relay_host": "support-gateway.example.test",
            "relay_port": 2222,
            "relay_username": "kato-relay",
            "bind_host": "127.77.0.1",
            "bind_port": 45123,
            "support_server": "support-gateway.example.test",
            "support_port": 45123,
            "support_public_key": SUPPORT_KEY,
            "revoke_token": "private-revoke-token-123456789",
        }

    def revoke_session(self, session_id: str, revoke_token: str) -> None:
        self.revoked.append((session_id, revoke_token))


class FakeTunnel:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.started = False
        self.closed = False

    def start(self) -> None:
        if self.fail:
            raise SetupError("relay_tunnel_failed", "Тестовый отказ туннеля.")
        self.started = True

    def close(self) -> None:
        self.closed = True

    def is_active(self) -> bool:
        return self.started and not self.closed


class RouterSupportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = ConnectionSpec("192.168.11.1", "root", "router-secret", "", 22)
        self.config = SupportRelayConfig(
            enabled=True,
            api_url="https://support-api.example.test/v1",
            relay_host_key_sha256="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

    def test_bundled_release_config_enables_the_verified_public_relay(self) -> None:
        config = load_support_relay_config(TOOL_ROOT / "profile" / "support-relay.json")

        self.assertTrue(config.enabled)
        self.assertEqual("https://router-support.katovpn.app/v1", config.api_url)
        self.assertRegex(config.relay_host_key_sha256, r"^SHA256:[A-Za-z0-9+/]{43}$")

    def test_support_key_validation_accepts_one_public_key_and_rejects_options_or_multiline(self) -> None:
        normalized = validate_support_public_key(SUPPORT_KEY)
        self.assertTrue(normalized.startswith("ssh-rsa "))
        self.assertNotIn("Kato Support", normalized)

        for unsafe in (
            "command=\"sh\" " + SUPPORT_KEY,
            SUPPORT_KEY + "\nssh-rsa AAAA second",
            "ssh-ed25519 not-base64",
            "ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
        ):
            with self.assertRaises(SetupError):
                validate_support_public_key(unsafe)

    def test_router_cleanup_is_exact_timed_and_survives_reboot_via_cron(self) -> None:
        install = build_support_install_command("a1b2c3d4e5f60708", 4102444800)
        remove = build_support_remove_command("a1b2c3d4e5f60708")

        self.assertIn("KatoVPN-Support-a1b2c3d4e5f60708", install)
        self.assertIn("/etc/dropbear/authorized_keys", install)
        self.assertIn("/etc/crontabs/root", install)
        self.assertIn("4102444800", install)
        self.assertIn("start-stop-daemon", install)
        self.assertIn("session.sh", install)
        self.assertIn("timeout -s KILL", install)
        self.assertIn("SSH_ORIGINAL_COMMAND", install)
        self.assertNotIn(self.spec.password, install)
        self.assertIn("--force", remove)
        self.assertNotIn("rm -rf /root;", install + remove)
        self.assertNotIn("rm -rf /root ", install + remove)

    def test_router_key_install_requires_clock_and_writes_only_public_material(self) -> None:
        class FakeRouterSession:
            def __init__(self, _spec: ConnectionSpec) -> None:
                self.fingerprint = "SHA256:router"
                self.writes: dict[str, bytes] = {}
                self.commands: list[str] = []

            def connect(self) -> None:
                return None

            def close(self) -> None:
                return None

            def write_file(self, path: str, data: bytes, mode: str = "600") -> None:
                del mode
                self.writes[path] = data

            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                del timeout, check
                self.commands.append(command)
                if label == "проверка временного доступа":
                    return f"uid=0\ndropbear=1\ncron=1\ncron_enabled=1\ndaemon=1\ntimeout=1\nnow={int(time.time())}"
                if label == "проверка временного ключа":
                    return "1"
                return ""

        sessions: list[FakeRouterSession] = []

        def factory(spec: ConnectionSpec) -> FakeRouterSession:
            session = FakeRouterSession(spec)
            sessions.append(session)
            return session

        install_temporary_support_key(
            self.spec,
            "SHA256:router",
            SUPPORT_KEY,
            "session-12345678",
            int(time.time()) + 3600,
            session_factory=factory,
        )

        written = sessions[0].writes["/tmp/kato-support-key"].decode("ascii")
        self.assertIn("KatoVPN-Support-session-12345678", written)
        self.assertIn('command="/root/katovpn-support/session-12345678/session.sh"', written)
        self.assertIn("no-port-forwarding", written)
        self.assertNotIn(self.spec.password, written + "".join(sessions[0].commands))

    def test_router_capability_error_identifies_only_missing_safe_prerequisites(self) -> None:
        class MissingTimeoutRouterSession:
            def __init__(self, _spec: ConnectionSpec) -> None:
                self.fingerprint = "SHA256:router"

            def connect(self) -> None:
                return None

            def close(self) -> None:
                return None

            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                del label, timeout, check
                if "printf 'uid=%s" in command:
                    return (
                        "uid=0\ndropbear=1\ncron=1\ncron_enabled=1\n"
                        f"daemon=1\ntimeout=0\nnow={int(time.time())}"
                    )
                return ""

        with self.assertRaises(SetupError) as caught:
            install_temporary_support_key(
                self.spec,
                "SHA256:router",
                SUPPORT_KEY,
                "session-12345678",
                int(time.time()) + 3600,
                session_factory=MissingTimeoutRouterSession,
            )

        error = caught.exception
        self.assertEqual("support_router_unsupported", error.code)
        self.assertEqual(["timeout"], error.details["missing_capabilities"])
        self.assertIn("timeout", error.message)
        self.assertNotIn(self.spec.password, json.dumps(error.as_dict(), ensure_ascii=False))

    def test_router_key_install_accepts_busybox_timeout_applet_without_path_alias(self) -> None:
        class BusyBoxTimeoutRouterSession:
            def __init__(self, _spec: ConnectionSpec) -> None:
                self.fingerprint = "SHA256:router"
                self.commands: list[str] = []

            def connect(self) -> None:
                return None

            def close(self) -> None:
                return None

            def write_file(self, _path: str, _data: bytes, mode: str = "600") -> None:
                del mode

            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                del label, timeout, check
                self.commands.append(command)
                if "printf 'uid=%s" in command:
                    return (
                        "uid=0\ndropbear=1\ncron=1\ncron_enabled=1\n"
                        f"daemon=1\ntimeout=busybox\nnow={int(time.time())}"
                    )
                if "grep -F -c" in command:
                    return "1"
                return ""

        sessions: list[BusyBoxTimeoutRouterSession] = []

        def factory(spec: ConnectionSpec) -> BusyBoxTimeoutRouterSession:
            session = BusyBoxTimeoutRouterSession(spec)
            sessions.append(session)
            return session

        install_temporary_support_key(
            self.spec,
            "SHA256:router",
            SUPPORT_KEY,
            "session-12345678",
            int(time.time()) + 3600,
            session_factory=factory,
        )

        self.assertTrue(any("busybox timeout -s KILL" in command for command in sessions[0].commands))

    def test_router_key_install_uses_pid_safe_shell_watchdog_when_timeout_is_absent(self) -> None:
        class ShellWatchdogRouterSession:
            def __init__(self, _spec: ConnectionSpec) -> None:
                self.fingerprint = "SHA256:router"
                self.commands: list[str] = []

            def connect(self) -> None:
                return None

            def close(self) -> None:
                return None

            def write_file(self, _path: str, _data: bytes, mode: str = "600") -> None:
                del mode

            def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
                del label, timeout, check
                self.commands.append(command)
                if "printf 'uid=%s" in command:
                    return (
                        "uid=0\ndropbear=1\ncron=1\ncron_enabled=1\n"
                        f"daemon=1\ntimeout=0\nwatchdog=1\nnow={int(time.time())}"
                    )
                if "grep -F -c" in command:
                    return "1"
                return ""

        sessions: list[ShellWatchdogRouterSession] = []

        def factory(spec: ConnectionSpec) -> ShellWatchdogRouterSession:
            session = ShellWatchdogRouterSession(spec)
            sessions.append(session)
            return session

        install_temporary_support_key(
            self.spec,
            "SHA256:router",
            SUPPORT_KEY,
            "session-12345678",
            int(time.time()) + 3600,
            session_factory=factory,
        )

        install_command = "".join(sessions[0].commands)
        self.assertIn("KATO_SUPPORT_WATCHDOG", install_command)
        self.assertIn("/proc/$SESSION_PID/stat", install_command)
        self.assertIn('"$CURRENT_START" = "$SESSION_START"', install_command)
        self.assertIn('kill -KILL "$SESSION_PID"', install_command)

    def test_manager_starts_and_stops_without_exposing_secrets(self) -> None:
        relay = FakeRelay()
        tunnel = FakeTunnel()
        installed: list[tuple[str, str, int]] = []
        removed: list[str] = []
        timers: list[FakeTimer] = []

        def timer_factory(delay: float, callback):
            timer = FakeTimer(delay, callback)
            timers.append(timer)
            return timer

        manager = SupportSessionManager(
            self.config,
            relay_client=relay,
            tunnel_factory=lambda **_kwargs: tunnel,
            install_key=lambda _spec, _fingerprint, key, session_id, expires_at: installed.append(
                (session_id, key, expires_at)
            ),
            remove_key=lambda _spec, _fingerprint, session_id: removed.append(session_id),
            timer_factory=timer_factory,
            now=lambda: 4102441200,
        )

        public = manager.start(self.spec, "SHA256:router", router_username="root")
        serialized = json.dumps(public)
        self.assertTrue(tunnel.started)
        self.assertEqual(3600, relay.duration_seconds)
        self.assertEqual("session-12345678", installed[0][0])
        self.assertTrue(timers[0].started)
        self.assertEqual("active", public["status"])
        self.assertEqual("KATO-7H2K9M", public["code"])
        self.assertNotIn("private-revoke-token-123456789", serialized)
        self.assertNotIn("support_public_key", serialized)
        self.assertNotIn("router-secret", serialized)

        stopped = manager.stop()
        self.assertTrue(tunnel.closed)
        self.assertTrue(timers[0].cancelled)
        self.assertEqual(["session-12345678"], removed)
        self.assertEqual([("session-12345678", "private-revoke-token-123456789")], relay.revoked)
        self.assertEqual("inactive", stopped["status"])

    def test_failed_tunnel_rolls_back_router_key_and_relay_lease(self) -> None:
        relay = FakeRelay()
        removed: list[str] = []
        manager = SupportSessionManager(
            self.config,
            relay_client=relay,
            tunnel_factory=lambda **_kwargs: FakeTunnel(fail=True),
            install_key=lambda *_args: None,
            remove_key=lambda _spec, _fingerprint, session_id: removed.append(session_id),
            timer_factory=FakeTimer,
            now=lambda: 4102441200,
        )

        with self.assertRaises(SetupError):
            manager.start(self.spec, "SHA256:router", router_username="root")

        self.assertEqual(["session-12345678"], removed)
        self.assertEqual([("session-12345678", "private-revoke-token-123456789")], relay.revoked)
        self.assertEqual("inactive", manager.public_status()["status"])

    def test_app_shutdown_and_logout_close_support_before_forgetting_router(self) -> None:
        class FakeSupportManager:
            def __init__(self) -> None:
                self.shutdown_calls = 0
                self.stop_calls = 0

            def public_status(self):
                return {"status": "inactive", "available": True}

            def shutdown(self) -> None:
                self.shutdown_calls += 1

            def stop(self, **_kwargs):
                self.stop_calls += 1
                return self.public_status()

        support = FakeSupportManager()
        state = AppState(support_manager=support)
        state.save_router_session(self.spec, "SHA256:router", {"connected": True})
        state.clear_router_session()
        self.assertEqual(1, support.stop_calls)

        state.request_shutdown(explicit=True)
        self.assertEqual(1, support.shutdown_calls)

    def test_internet_ui_contains_temporary_support_flow_and_plain_safety_copy(self) -> None:
        html = (TOOL_ROOT / "web" / "index.html").read_text(encoding="utf-8")
        script = (TOOL_ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="support-access"', html)
        self.assertIn('id="support-start-button"', html)
        self.assertIn('id="support-stop-button"', html)
        self.assertIn('id="support-copy-button"', html)
        self.assertIn("Разрешить подключение", html)
        self.assertIn("Завершить доступ", html)
        self.assertIn("пароль роутера не передаётся", html)
        self.assertIn("При отключении, закрытии программы или окончании часа", html)
        self.assertIn("/api/support/start", script)
        self.assertIn("/api/support/stop", script)
        self.assertIn("support-countdown", script)


if __name__ == "__main__":
    unittest.main()
