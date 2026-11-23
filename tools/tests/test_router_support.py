from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


TOOL_ROOT = Path(__file__).resolve().parents[1] / "nikki-router-setup"
sys.path.insert(0, str(TOOL_ROOT))

from katovpn_router_setup.core import ConnectionSpec, SetupError  # noqa: E402
from katovpn_router_setup.server import AppState  # noqa: E402
from katovpn_router_setup.support import (  # noqa: E402
    SupportRelayConfig,
    SupportSessionManager,
    ReverseSshTunnel,
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

    def router_reachable(self) -> bool:
        return True


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

    def test_tcp_accept_without_ssh_banner_is_not_healthy(self) -> None:
        tunnel = ReverseSshTunnel(
            config=self.config, lease={}, client_key=Mock(), router_spec=self.spec,
        )
        for banner, expected in ((b"", False), (b"HTTP/1.1 200 OK\r\n", False),
                                 (b"SSH-2.0-dropbear\r\n", True)):
            with self.subTest(banner=banner):
                sock = Mock()
                sock.__enter__ = Mock(return_value=sock)
                sock.__exit__ = Mock(return_value=False)
                sock.recv.return_value = banner
                with patch("katovpn_router_setup.support.socket.create_connection", return_value=sock):
                    self.assertEqual(expected, tunnel.router_reachable())

    def test_ssh_banner_can_arrive_in_multiple_packets(self) -> None:
        tunnel = ReverseSshTunnel(config=self.config, lease={}, client_key=Mock(), router_spec=self.spec)
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        sock.recv.side_effect = [b"SSH-", b"2.0-dropbear\r\n"]
        with patch("katovpn_router_setup.support.socket.create_connection", return_value=sock):
            self.assertTrue(tunnel.router_reachable())

    @patch("katovpn_router_setup.support.time", wraps=time)
    def test_monotonic_hour_expires_even_if_wall_clock_moves_back(self, clock) -> None:
        relay, tunnel = FakeRelay(), FakeTunnel()
        now = [4102441200]
        clock.monotonic.return_value = 0
        removed = threading.Event()
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: tunnel,
            install_key=lambda *args: None, remove_key=lambda *args: removed.set(),
            timer_factory=FakeTimer, now=lambda: now[0], monitor_interval_seconds=0.01,
        )
        self.addCleanup(manager.shutdown)
        manager.start(self.spec, "SHA256:router", router_username="root")
        now[0] -= 600
        clock.monotonic.return_value = 3601
        self.assertTrue(removed.wait(1))
        self.assertEqual("expired", manager.public_status()["stop_reason"])
        self.assertEqual(1, len(relay.revoked))

    def test_stop_during_key_repair_cleans_up_after_repair_finishes(self) -> None:
        relay, tunnel = FakeRelay(), FakeTunnel()
        entered, release, removed, stopped = (threading.Event() for _ in range(4))
        def repair(*args):
            entered.set()
            release.wait(2)
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: tunnel,
            install_key=lambda *args: None, repair_key=repair,
            remove_key=lambda *args: removed.set(), timer_factory=FakeTimer,
            now=lambda: 4102441200, monitor_interval_seconds=0.01,
        )
        self.addCleanup(manager.shutdown)
        self.addCleanup(release.set)
        manager.start(self.spec, "SHA256:router", router_username="root")
        self.assertTrue(entered.wait(1))
        def stop():
            manager.stop()
            stopped.set()
        worker = threading.Thread(target=stop)
        worker.start()
        try:
            deadline = time.monotonic() + 1
            while manager.active is not None and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertIsNone(manager.active)
            self.assertFalse(removed.is_set())
        finally:
            release.set()
            worker.join(2)
        self.assertTrue(stopped.is_set())
        self.assertTrue(removed.is_set())
        self.assertEqual("inactive", manager.public_status()["status"])

    def test_stop_during_start_never_publishes_late_tunnel(self) -> None:
        relay, tunnel = FakeRelay(), FakeTunnel()
        entered, release = threading.Event(), threading.Event()
        removed, errors = [], []
        def connect():
            entered.set()
            release.wait(2)
            tunnel.started = True
        tunnel.start = connect
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: tunnel,
            install_key=lambda *args: None, remove_key=lambda *args: removed.append(args),
            timer_factory=FakeTimer, now=lambda: 4102441200,
        )
        self.addCleanup(manager.shutdown)
        self.addCleanup(release.set)
        def start():
            try:
                manager.start(self.spec, "SHA256:router", router_username="root")
            except SetupError as exc:
                errors.append(exc.code)
        worker = threading.Thread(target=start)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            manager.stop()
        finally:
            release.set()
            worker.join(2)
        self.assertEqual(["support_cancelled"], errors)
        self.assertEqual("inactive", manager.public_status()["status"])
        self.assertTrue(tunnel.closed)
        self.assertEqual(1, len(removed))
        self.assertEqual(1, len(relay.revoked))

    def test_recovery_close_failure_does_not_discard_original_hour(self) -> None:
        relay = FakeRelay()
        first, replacement = FakeTunnel(), FakeTunnel()
        first.close = Mock(side_effect=OSError("private transport detail"))
        tunnels = iter((first, replacement))
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: next(tunnels),
            install_key=lambda *args: None, remove_key=lambda *args: None,
            timer_factory=FakeTimer, now=lambda: 4102441200, monitor_interval_seconds=60,
        )
        self.addCleanup(manager.shutdown)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        self.assertTrue(manager._recover_tunnel(manager.active, manager.active["monitor_stop"]))
        self.assertIs(replacement, manager.active["tunnel"])
        self.assertEqual(original["expires_at"], manager.public_status()["expires_at"])
        self.assertEqual([], relay.revoked)

    def test_repair_failure_is_visible_without_secrets_and_retries_same_lease(self) -> None:
        relay, tunnel = FakeRelay(), FakeTunnel()
        checked, retry_release = threading.Event(), threading.Event()
        calls = []

        def repair(*args):
            calls.append(args)
            if len(calls) == 1:
                raise SetupError("ssh_auth", "private router-secret value")
            retry_release.wait(2)
            checked.set()

        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: tunnel,
            install_key=lambda *args: None, repair_key=repair, remove_key=lambda *args: None,
            timer_factory=FakeTimer, now=lambda: 4102441200, monitor_interval_seconds=0.01,
        )
        self.addCleanup(manager.shutdown)
        self.addCleanup(retry_release.set)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        deadline = time.monotonic() + 1
        failure = None
        while time.monotonic() < deadline:
            status = manager.public_status()
            if status.get("connection_state") == "recovering":
                failure = status
                break
            time.sleep(0.001)
        self.assertIsNotNone(failure)
        self.assertEqual("ssh_auth", failure["last_error_code"])
        self.assertNotIn("router-secret", json.dumps(failure))
        retry_release.set()
        self.assertTrue(checked.wait(1))
        self.assertEqual(original["code"], manager.public_status()["code"])
        self.assertEqual([], relay.revoked)
        self.assertEqual(calls[0], calls[1])

    def test_repair_can_restore_missing_key_in_last_minute(self) -> None:
        now = int(time.time())
        session = Mock(fingerprint="SHA256:router")
        session.run.side_effect = [
            "missing", f"uid=0\ndropbear=1\ncron=1\ncron_enabled=1\ndaemon=1\ntimeout=1\nnow={now}",
            "", "1", "",
        ]
        install_temporary_support_key(
            self.spec, "SHA256:router", SUPPORT_KEY, "session-12345678",
            now + 30, session_factory=lambda _: session, repair=True,
        )
        session.write_file.assert_called_once()

    @patch("katovpn_router_setup.support.time", wraps=time)
    def test_delayed_capability_response_cannot_install_after_expiry(self, clock) -> None:
        now = int(time.time())
        clock.time.return_value = now
        session = Mock(fingerprint="SHA256:router")
        def run(command, **kwargs):
            if kwargs["label"] == "проверка ключа после переподключения":
                return "missing"
            clock.time.return_value = now + 31
            return f"uid=0\ndropbear=1\ncron=1\ncron_enabled=1\ndaemon=1\ntimeout=1\nnow={now}"
        session.run.side_effect = run
        with self.assertRaises(SetupError) as error:
            install_temporary_support_key(
                self.spec, "SHA256:router", SUPPORT_KEY, "session-12345678",
                now + 30, session_factory=lambda _: session, repair=True,
            )
        self.assertEqual("support_expired", error.exception.code)
        session.write_file.assert_not_called()

    def test_suspended_forward_never_connects_to_unverified_router(self) -> None:
        tunnel = ReverseSshTunnel(config=self.config, lease={}, client_key=Mock(), router_spec=self.spec)
        tunnel.set_router_ready(False)
        channel = Mock()
        with patch("katovpn_router_setup.support.socket.create_connection") as connect:
            tunnel._forward_channel(channel)
        connect.assert_not_called()
        channel.close.assert_called_once()

    def test_repair_watchdog_closes_stalled_session_without_key_writes(self) -> None:
        closed = threading.Event()
        session = Mock(fingerprint="SHA256:router")
        session.close.side_effect = closed.set
        def stalled(command, **kwargs):
            if not closed.wait(1):
                self.fail("Session watchdog did not close a stalled command")
            return "missing"
        session.run.side_effect = stalled
        with self.assertRaises(SetupError) as error:
            install_temporary_support_key(
                self.spec, "SHA256:router", SUPPORT_KEY, "session-12345678",
                int(time.time()) + 1800, session_factory=lambda _: session, repair=True,
                session_timeout_seconds=0.02,
            )
        self.assertEqual("support_router_timeout", error.exception.code)
        session.write_file.assert_not_called()

    def test_key_generation_failure_does_not_leave_starting_stuck(self) -> None:
        manager = SupportSessionManager(
            self.config, key_factory=Mock(side_effect=RuntimeError("private generator failure")),
        )
        with self.assertRaises(SetupError):
            manager.start(self.spec, "SHA256:router", router_username="root")
        self.assertEqual("inactive", manager.public_status()["status"])

    def test_new_grant_is_blocked_until_previous_cleanup_finishes(self) -> None:
        entered, release = threading.Event(), threading.Event()
        def cleanup(*args):
            entered.set()
            release.wait(2)
        manager = SupportSessionManager(
            self.config, relay_client=FakeRelay(), tunnel_factory=lambda **_: FakeTunnel(),
            install_key=lambda *args: None, remove_key=cleanup,
            timer_factory=FakeTimer, now=lambda: 4102441200,
        )
        self.addCleanup(manager.shutdown)
        self.addCleanup(release.set)
        manager.start(self.spec, "SHA256:router", router_username="root")
        worker = threading.Thread(target=manager.stop)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            with self.assertRaises(SetupError) as error:
                manager.start(self.spec, "SHA256:router", router_username="root")
            self.assertEqual("support_already_active", error.exception.code)
        finally:
            release.set()
            worker.join(2)

    def test_firmware_repair_preserves_live_lease_or_reinstalls_missing_files(self) -> None:
        expires = int(time.time()) + 1800
        for state in ("present", "missing"):
            with self.subTest(state=state):
                session = Mock(fingerprint="SHA256:router")
                session.run.side_effect = [
                    state, f"uid=0\ndropbear=1\ncron=1\ncron_enabled=1\ndaemon=1\ntimeout=1\nnow={int(time.time())}",
                    "", "1", "",
                ]
                install_temporary_support_key(
                    self.spec, "SHA256:router", SUPPORT_KEY, "session-12345678",
                    expires, session_factory=lambda _: session, repair=True,
                )
                session.client.set_missing_host_key_policy.assert_called_once()
                probe = session.run.call_args_list[0].args[0]
                self.assertIn("/session.sh", probe)
                self.assertIn("/cleanup.sh", probe)
                self.assertIn(f"EXPIRES={expires}", probe)
                if state == "present":
                    session.write_file.assert_not_called()
                else:
                    session.write_file.assert_called_once()
                    self.assertIn(f"EXPIRES={expires}", session.run.call_args_list[2].args[0])

    def test_firmware_repair_rejects_changed_host_before_sending_credentials(self) -> None:
        session = Mock()
        session.connect.side_effect = lambda: session.client.set_missing_host_key_policy.call_args.args[0].missing_host_key(
            session.client, self.spec.host, Mock(**{"asbytes.return_value": b"another router key"}),
        )
        with self.assertRaises(SetupError) as raised:
            install_temporary_support_key(
                self.spec, "SHA256:router", SUPPORT_KEY, "session-12345678",
                int(time.time()) + 1800, session_factory=lambda _: session, repair=True,
            )
        self.assertEqual("router_fingerprint_changed", raised.exception.code)
        session.run.assert_not_called()
        session.write_file.assert_not_called()

    @patch("katovpn_router_setup.support.time", wraps=time)
    def test_disconnected_tunnel_recovers_with_same_lease_after_half_hour(self, clock) -> None:
        relay = FakeRelay()
        first, failed, replacement = FakeTunnel(), FakeTunnel(fail=True), FakeTunnel()
        tunnels = iter((first, failed, replacement))
        clock.monotonic.return_value = 0.0
        factory_args = []
        installed = []
        recovered = threading.Event()

        def factory(**kwargs):
            factory_args.append(kwargs)
            tunnel = next(tunnels)
            if tunnel is failed:
                clock.monotonic.return_value = 1800.0
            return tunnel

        def probe_replacement():
            recovered.set()
            return True

        replacement.router_reachable = probe_replacement
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=factory,
            install_key=lambda *args: installed.append(args), remove_key=lambda *args: None,
            timer_factory=FakeTimer, now=lambda: 4102441200, monitor_interval_seconds=0.02,
        )
        self.addCleanup(manager.shutdown)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        first.close()
        self.assertTrue(recovered.wait(1))
        current = manager.public_status()
        self.assertEqual(original, {**current, "diagnostics": []})
        self.assertEqual(1, len(installed))
        self.assertEqual([], relay.revoked)
        self.assertTrue(failed.closed)
        self.assertIs(factory_args[0]["lease"], factory_args[2]["lease"])
        self.assertIs(factory_args[0]["client_key"], factory_args[2]["client_key"])

    def test_router_outage_keeps_forward_then_releases_lease(self) -> None:
        relay = FakeRelay()
        tunnel = FakeTunnel()
        first_probe = threading.Event()
        removed = threading.Event()

        def unreachable():
            first_probe.set()
            return False

        tunnel.router_reachable = unreachable
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: tunnel,
            install_key=lambda *args: None, remove_key=lambda *args: removed.set(),
            timer_factory=FakeTimer, now=lambda: 4102441200,
            monitor_interval_seconds=0.01, recovery_window_seconds=0.15,
        )
        self.addCleanup(manager.shutdown)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        self.assertTrue(first_probe.wait(1))
        current = manager.public_status()
        for field in ("status", "code", "port", "expires_at"):
            self.assertEqual(original[field], current[field])
        self.assertEqual("recovering", current["connection_state"])
        self.assertTrue(removed.wait(2))
        self.assertTrue(tunnel.closed)
        self.assertEqual(1, len(relay.revoked))
        self.assertEqual("inactive", manager.public_status()["status"])

    @patch("katovpn_router_setup.support.time", wraps=time)
    def test_router_returns_after_half_hour_without_replacing_live_forward(self, clock) -> None:
        relay = FakeRelay()
        tunnel = FakeTunnel()
        returned = threading.Event()
        probes = iter(((0.0, False), (1800.0, False), (1800.0, True)))
        creations = []

        def probe():
            elapsed, reachable = next(probes, (1800.0, True))
            clock.monotonic.return_value = elapsed
            if reachable:
                returned.set()
            return reachable

        def factory(**kwargs):
            creations.append(kwargs)
            return tunnel

        tunnel.router_reachable = probe
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=factory,
            install_key=lambda *args: None, remove_key=lambda *args: None,
            timer_factory=FakeTimer, now=lambda: 4102441200, monitor_interval_seconds=0.01,
        )
        self.addCleanup(manager.shutdown)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        self.assertTrue(returned.wait(1))
        current = manager.public_status()
        self.assertEqual(original, {**current, "diagnostics": []})
        self.assertFalse(tunnel.closed)
        self.assertEqual(1, len(creations))
        self.assertEqual([], relay.revoked)

    def test_stop_while_recovery_is_connecting_discards_replacement(self) -> None:
        first, next_tunnel = FakeTunnel(), FakeTunnel()
        tunnels = iter((first, next_tunnel))
        connecting, release, closed = threading.Event(), threading.Event(), threading.Event()

        def start_replacement():
            connecting.set()
            release.wait(2)
            next_tunnel.started = True

        def close_replacement():
            next_tunnel.closed = True
            closed.set()

        next_tunnel.start = start_replacement
        next_tunnel.close = close_replacement
        relay = FakeRelay()
        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=lambda **_: next(tunnels),
            install_key=lambda *args: None, remove_key=lambda *args: None,
            timer_factory=FakeTimer, now=lambda: 4102441200, monitor_interval_seconds=0.01,
        )
        self.addCleanup(manager.shutdown)
        self.addCleanup(release.set)
        manager.start(self.spec, "SHA256:router", router_username="root")
        first.close()
        self.assertTrue(connecting.wait(1))
        self.assertEqual("inactive", manager.stop()["status"])
        release.set()
        self.assertTrue(closed.wait(1))
        self.assertEqual(1, len(relay.revoked))

    def test_expired_lease_never_reconnects(self) -> None:
        relay = FakeRelay()
        tunnel = FakeTunnel()
        now = [4102441200]
        removed = threading.Event()
        attempts = []

        def factory(**kwargs):
            attempts.append(kwargs)
            return tunnel

        manager = SupportSessionManager(
            self.config, relay_client=relay, tunnel_factory=factory,
            install_key=lambda *args: None, remove_key=lambda *args: removed.set(),
            timer_factory=FakeTimer, now=lambda: now[0], monitor_interval_seconds=0.02,
        )
        self.addCleanup(manager.shutdown)
        original = manager.start(self.spec, "SHA256:router", router_username="root")
        now[0] = original["expires_at"]
        tunnel.close()
        self.assertTrue(removed.wait(1))
        self.assertEqual(1, len(attempts))
        self.assertEqual(1, len(relay.revoked))
        self.assertEqual("inactive", manager.public_status()["status"])

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
