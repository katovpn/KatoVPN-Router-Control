from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import secrets
import select
import shlex
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

import paramiko
import requests

from .core import ConnectionSpec, RemoteSession, SetupError, resource_root


SUPPORT_DURATION_SECONDS = 60 * 60
SUPPORT_KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}
SUPPORT_SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
SUPPORT_CODE_PATTERN = re.compile(r"^[A-Z0-9-]{6,32}$")
SUPPORT_HOST_KEY_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]{42,44}$")
SUPPORT_ROOT = "/root/katovpn-support"
SUPPORT_AUTHORIZED_KEYS = "/etc/dropbear/authorized_keys"
SUPPORT_CRONTAB = "/etc/crontabs/root"


@dataclass(frozen=True)
class SupportRelayConfig:
    enabled: bool = False
    api_url: str = ""
    relay_host_key_sha256: str = ""
    request_timeout_seconds: int = 12


class RelayClient(Protocol):
    def create_session(self, client_public_key: str, *, duration_seconds: int) -> Mapping[str, Any]: ...

    def revoke_session(self, session_id: str, revoke_token: str) -> None: ...


class Tunnel(Protocol):
    def start(self) -> None: ...

    def close(self) -> None: ...

    def is_active(self) -> bool: ...


def _validate_support_session_id(value: str) -> str:
    value = str(value)
    if not SUPPORT_SESSION_PATTERN.fullmatch(value):
        raise SetupError("invalid_support_session", "Сервер поддержки вернул некорректный идентификатор сессии.")
    return value


def _validate_public_hostname(value: str, *, field: str) -> str:
    value = str(value).strip()
    if not value or len(value) > 253 or "://" in value or any(ch.isspace() for ch in value):
        raise SetupError("invalid_support_relay", f"Сервер поддержки вернул некорректное поле «{field}».")
    labels = value.rstrip(".").split(".")
    label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        try:
            socket.inet_pton(socket.AF_INET, value)
        except OSError as exc:
            raise SetupError("invalid_support_relay", f"Сервер поддержки вернул некорректное поле «{field}».") from exc
    return value


def _validate_port(value: Any, *, field: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise SetupError("invalid_support_relay", f"Сервер поддержки вернул некорректное поле «{field}».") from exc
    if not 1 <= port <= 65535:
        raise SetupError("invalid_support_relay", f"Сервер поддержки вернул некорректное поле «{field}».")
    return port


def validate_support_public_key(value: str) -> str:
    """Return one normalized public key without user-controlled options or comments."""
    value = str(value).strip()
    if "\n" in value or "\r" in value or len(value) > 4096:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.")
    parts = value.split()
    if len(parts) < 2 or parts[0] not in SUPPORT_KEY_TYPES:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.") from exc
    if len(decoded) < 32:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.")
    try:
        parsed_key = paramiko.PKey.from_type_string(parts[0], decoded)
    except Exception as exc:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.") from exc
    if parsed_key.get_name() != parts[0]:
        raise SetupError("invalid_support_key", "Сервер поддержки вернул некорректный публичный ключ.")
    return f"{parts[0]} {parts[1]}"


def load_support_relay_config(path: Path | None = None) -> SupportRelayConfig:
    config_path = path or (resource_root() / "profile" / "support-relay.json")
    if not config_path.is_file():
        return SupportRelayConfig()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return SupportRelayConfig()
    if not isinstance(raw, Mapping) or raw.get("enabled") is not True:
        return SupportRelayConfig()
    api_url = str(raw.get("api_url", "")).strip().rstrip("/")
    host_key = str(raw.get("relay_host_key_sha256", "")).strip()
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        return SupportRelayConfig()
    if not SUPPORT_HOST_KEY_PATTERN.fullmatch(host_key):
        return SupportRelayConfig()
    return SupportRelayConfig(enabled=True, api_url=api_url, relay_host_key_sha256=host_key)


def build_support_install_command(session_id: str, expires_at: int) -> str:
    session_id = _validate_support_session_id(session_id)
    try:
        expires_at = int(expires_at)
    except (TypeError, ValueError) as exc:
        raise SetupError("invalid_support_expiry", "Сервер поддержки вернул некорректное время завершения.") from exc
    if expires_at < 1:
        raise SetupError("invalid_support_expiry", "Сервер поддержки вернул некорректное время завершения.")
    marker = f"KatoVPN-Support-{session_id}"
    support_dir = f"{SUPPORT_ROOT}/{session_id}"
    cleanup = f"{support_dir}/cleanup.sh"
    session_shell = f"{support_dir}/session.sh"
    delay = max(1, expires_at - int(time.time()))
    return (
        f"mkdir -p {shlex.quote(support_dir)} /etc/dropbear /etc/crontabs; "
        f"chmod 700 {shlex.quote(SUPPORT_ROOT)} {shlex.quote(support_dir)}; "
        f"cat > {shlex.quote(session_shell)} <<'KATO_SUPPORT_SESSION'\n"
        "#!/bin/sh\n"
        f"EXPIRES={expires_at}\n"
        "NOW=$(date +%s 2>/dev/null || printf '0')\n"
        "REMAINING=$((EXPIRES - NOW))\n"
        "[ \"$REMAINING\" -gt 0 ] || exit 124\n"
        "if [ -n \"${SSH_ORIGINAL_COMMAND:-}\" ]; then\n"
        "  exec timeout -s KILL \"$REMAINING\" /bin/ash -c \"$SSH_ORIGINAL_COMMAND\"\n"
        "fi\n"
        "exec timeout -s KILL \"$REMAINING\" /bin/ash -l\n"
        "KATO_SUPPORT_SESSION\n"
        f"chmod 700 {shlex.quote(session_shell)}; "
        f"touch {shlex.quote(SUPPORT_AUTHORIZED_KEYS)} {shlex.quote(SUPPORT_CRONTAB)}; "
        f"chmod 600 {shlex.quote(SUPPORT_AUTHORIZED_KEYS)}; "
        f"sed -i '\\| {marker}$|d' {shlex.quote(SUPPORT_AUTHORIZED_KEYS)}; "
        f"cat /tmp/kato-support-key >> {shlex.quote(SUPPORT_AUTHORIZED_KEYS)}; "
        f"cat > {shlex.quote(cleanup)} <<'KATO_SUPPORT_CLEANUP'\n"
        "#!/bin/sh\n"
        f"EXPIRES={expires_at}\n"
        f"MARKER='{marker}'\n"
        f"AUTH='{SUPPORT_AUTHORIZED_KEYS}'\n"
        f"CRON='{SUPPORT_CRONTAB}'\n"
        f"DIR='{support_dir}'\n"
        "if [ \"${1:-}\" != '--force' ]; then\n"
        "  NOW=$(date +%s 2>/dev/null || printf '0')\n"
        "  [ \"$NOW\" -ge \"$EXPIRES\" ] || exit 0\n"
        "fi\n"
        "if [ -f \"$AUTH\" ]; then\n"
        "  TMP=\"${AUTH}.kato.$$\"\n"
        "  sed \"\\| ${MARKER}$|d\" \"$AUTH\" > \"$TMP\" && cat \"$TMP\" > \"$AUTH\"\n"
        "  rm -f \"$TMP\"\n"
        "  chmod 600 \"$AUTH\" 2>/dev/null || true\n"
        "fi\n"
        "if [ -f \"$CRON\" ]; then\n"
        "  TMP=\"${CRON}.kato.$$\"\n"
        "  sed \"\\|# ${MARKER}$|d\" \"$CRON\" > \"$TMP\" && cat \"$TMP\" > \"$CRON\"\n"
        "  rm -f \"$TMP\"\n"
        "fi\n"
        "/etc/init.d/cron restart >/dev/null 2>&1 || true\n"
        "rm -rf \"$DIR\"\n"
        "KATO_SUPPORT_CLEANUP\n"
        f"chmod 700 {shlex.quote(cleanup)}; "
        f"sed -i '\\|# {marker}$|d' {shlex.quote(SUPPORT_CRONTAB)}; "
        f"printf '%s\n' '* * * * * {cleanup} # {marker}' >> {shlex.quote(SUPPORT_CRONTAB)}; "
        "/etc/init.d/cron restart >/dev/null 2>&1; "
        f"start-stop-daemon -S -b -x /bin/sh -- -c 'sleep {delay}; {cleanup} --force' >/dev/null 2>&1; "
        "rm -f /tmp/kato-support-key"
    )


def build_support_remove_command(session_id: str) -> str:
    session_id = _validate_support_session_id(session_id)
    marker = f"KatoVPN-Support-{session_id}"
    support_dir = f"{SUPPORT_ROOT}/{session_id}"
    cleanup = f"{support_dir}/cleanup.sh"
    return (
        f"if [ -x {shlex.quote(cleanup)} ]; then {shlex.quote(cleanup)} --force; else "
        f"[ ! -f {shlex.quote(SUPPORT_AUTHORIZED_KEYS)} ] || sed -i '\\| {marker}$|d' {shlex.quote(SUPPORT_AUTHORIZED_KEYS)}; "
        f"[ ! -f {shlex.quote(SUPPORT_CRONTAB)} ] || sed -i '\\|# {marker}$|d' {shlex.quote(SUPPORT_CRONTAB)}; "
        "/etc/init.d/cron restart >/dev/null 2>&1 || true; "
        f"rm -rf {shlex.quote(support_dir)}; fi; rm -f /tmp/kato-support-key"
    )


def install_temporary_support_key(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    public_key: str,
    session_id: str,
    expires_at: int,
    *,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> None:
    session_id = _validate_support_session_id(session_id)
    public_key = validate_support_public_key(public_key)
    marker = f"KatoVPN-Support-{session_id}"
    session = session_factory(spec)
    try:
        session.connect()
        if not secrets.compare_digest(expected_fingerprint, session.fingerprint):
            raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Временный доступ не включён.")
        capabilities = session.run(
            "printf 'uid=%s\\n' \"$(id -u)\"; "
            "printf 'dropbear=%s\\n' \"$([ -d /etc/dropbear ] && echo 1 || echo 0)\"; "
            "printf 'cron=%s\\n' \"$([ -x /etc/init.d/cron ] && echo 1 || echo 0)\"; "
            "printf 'cron_enabled=%s\\n' \"$(ls /etc/rc.d/S*cron >/dev/null 2>&1 && echo 1 || echo 0)\"; "
            "printf 'daemon=%s\\n' \"$(command -v start-stop-daemon >/dev/null 2>&1 && echo 1 || echo 0)\"; "
            "printf 'timeout=%s\\n' \"$(command -v timeout >/dev/null 2>&1 && echo 1 || echo 0)\"; "
            "printf 'now=%s\\n' \"$(date +%s 2>/dev/null || printf '0')\"",
            label="проверка временного доступа",
        )
        required = {"uid=0", "dropbear=1", "cron=1", "cron_enabled=1", "daemon=1", "timeout=1"}
        if not required.issubset(set(capabilities.splitlines())):
            raise SetupError(
                "support_router_unsupported",
                "Роутер не подтвердил безопасное добавление и автоматическое удаление временного ключа.",
            )
        clock_match = re.search(r"(?m)^now=(\d+)$", capabilities)
        router_now = int(clock_match.group(1)) if clock_match else 0
        if abs(router_now - int(time.time())) > 300 or not router_now + 60 <= int(expires_at) <= router_now + SUPPORT_DURATION_SECONDS + 120:
            raise SetupError("support_router_clock", "Время на роутере неверное, поэтому безопасный часовой таймер не может быть включён.")
        session_shell = f"{SUPPORT_ROOT}/{session_id}/session.sh"
        authorized_key = (
            f'command="{session_shell}",no-agent-forwarding,no-X11-forwarding,no-port-forwarding '
            f"{public_key} {marker}\n"
        )
        session.write_file("/tmp/kato-support-key", authorized_key.encode("ascii"))
        session.run(
            build_support_install_command(session_id, expires_at),
            label="временный ключ поддержки",
            timeout=25,
        )
        count = session.run(
            f"grep -F -c ' {marker}' {shlex.quote(SUPPORT_AUTHORIZED_KEYS)} 2>/dev/null || true",
            label="проверка временного ключа",
        )
        if count.strip() != "1":
            session.run(build_support_remove_command(session_id), label="отмена временного ключа", check=False)
            raise SetupError("support_key_not_installed", "Роутер не подтвердил временный ключ поддержки.")
    finally:
        try:
            session.run("rm -f /tmp/kato-support-key", label="очистка временного ключа", check=False)
        except Exception:
            pass
        session.close()


def remove_temporary_support_key(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    session_id: str,
    *,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> None:
    session_id = _validate_support_session_id(session_id)
    session = session_factory(spec)
    try:
        session.connect()
        if not secrets.compare_digest(expected_fingerprint, session.fingerprint):
            raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Временный ключ удалит таймер роутера.")
        session.run(build_support_remove_command(session_id), label="отключение временной поддержки", timeout=20)
    finally:
        session.close()


class SupportRelayApiClient:
    def __init__(self, config: SupportRelayConfig, *, post: Callable[..., Any] = requests.post, delete: Callable[..., Any] = requests.delete):
        self.config = config
        self._post = post
        self._delete = delete

    def create_session(self, client_public_key: str, *, duration_seconds: int) -> Mapping[str, Any]:
        if not self.config.enabled:
            raise SetupError("support_relay_unavailable", "Сервер временной поддержки ещё не подключён к этой сборке.")
        try:
            response = self._post(
                f"{self.config.api_url}/support/sessions",
                json={"client_public_key": client_public_key, "duration_seconds": duration_seconds},
                headers={"User-Agent": "KatoVPN-Router-Control/0.4"},
                timeout=self.config.request_timeout_seconds,
            )
            if int(response.status_code) not in {200, 201}:
                raise SetupError("support_relay_http", "Сервер поддержки временно не смог создать подключение.")
            payload = response.json()
        except SetupError:
            raise
        except Exception as exc:
            raise SetupError("support_relay_unreachable", "Не удалось связаться с сервером временной поддержки.") from exc
        if not isinstance(payload, Mapping):
            raise SetupError("invalid_support_relay", "Сервер поддержки вернул некорректный ответ.")
        return payload

    def revoke_session(self, session_id: str, revoke_token: str) -> None:
        session_id = _validate_support_session_id(session_id)
        try:
            response = self._delete(
                f"{self.config.api_url}/support/sessions/{urllib.parse.quote(session_id)}",
                headers={"Authorization": f"Bearer {revoke_token}", "User-Agent": "KatoVPN-Router-Control/0.4"},
                timeout=self.config.request_timeout_seconds,
            )
            if int(response.status_code) not in {200, 202, 204, 404, 410}:
                raise SetupError("support_revoke_failed", "Сервер поддержки не подтвердил закрытие подключения.")
        except SetupError:
            raise
        except Exception as exc:
            raise SetupError("support_revoke_failed", "Не удалось подтвердить закрытие на сервере поддержки.") from exc


def _server_key_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class ReverseSshTunnel:
    def __init__(
        self,
        *,
        config: SupportRelayConfig,
        lease: Mapping[str, Any],
        client_key: paramiko.PKey,
        router_spec: ConnectionSpec,
    ) -> None:
        self.config = config
        self.lease = dict(lease)
        self.client_key = client_key
        self.router_spec = router_spec
        self.transport: paramiko.Transport | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        sock: socket.socket | None = None
        transport: paramiko.Transport | None = None
        try:
            sock = socket.create_connection((self.lease["relay_host"], self.lease["relay_port"]), timeout=10)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=10)
            server_key = transport.get_remote_server_key()
            if not secrets.compare_digest(self.config.relay_host_key_sha256, _server_key_fingerprint(server_key)):
                raise SetupError("support_relay_fingerprint", "SSH-ключ сервера поддержки не совпал с доверенным.")
            transport.auth_publickey(self.lease["relay_username"], self.client_key)
            if not transport.is_authenticated():
                raise SetupError("support_relay_auth", "Сервер поддержки не принял временный ключ приложения.")
            transport.set_keepalive(15)
            transport.request_port_forward(self.lease["bind_host"], self.lease["bind_port"], handler=self._handle_channel)
            with self._lock:
                self.transport = transport
            transport = None
            sock = None
        except SetupError:
            raise
        except (OSError, socket.timeout, paramiko.SSHException) as exc:
            raise SetupError("relay_tunnel_failed", "Не удалось открыть защищённый туннель поддержки.") from exc
        finally:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()

    def _handle_channel(self, channel: paramiko.Channel, _origin: tuple[str, int], _server: tuple[str, int]) -> None:
        threading.Thread(target=self._forward_channel, args=(channel,), name="kato-support-forward", daemon=True).start()

    def _forward_channel(self, channel: paramiko.Channel) -> None:
        target: socket.socket | None = None
        try:
            target = socket.create_connection((self.router_spec.host, self.router_spec.port), timeout=8)
            while True:
                readable, _, _ = select.select([channel, target], [], [], 1.0)
                if channel in readable:
                    data = channel.recv(32768)
                    if not data:
                        break
                    target.sendall(data)
                if target in readable:
                    data = target.recv(32768)
                    if not data:
                        break
                    channel.sendall(data)
        except (OSError, socket.timeout, paramiko.SSHException):
            pass
        finally:
            try:
                channel.close()
            finally:
                if target is not None:
                    target.close()

    def close(self) -> None:
        with self._lock:
            transport = self.transport
            self.transport = None
        if transport is None:
            return
        try:
            transport.cancel_port_forward(self.lease["bind_host"], self.lease["bind_port"])
        except (OSError, paramiko.SSHException):
            pass
        transport.close()

    def is_active(self) -> bool:
        with self._lock:
            transport = self.transport
        return bool(transport and transport.is_active() and transport.is_authenticated())


def _normalize_lease(raw: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    try:
        expires_at = int(raw.get("expires_at"))
    except (TypeError, ValueError) as exc:
        raise SetupError("invalid_support_expiry", "Сервер поддержки вернул некорректное время завершения.") from exc
    if not now + 60 <= expires_at <= now + SUPPORT_DURATION_SECONDS + 120:
        raise SetupError("invalid_support_expiry", "Срок временного доступа не соответствует одному часу.")
    code = str(raw.get("code", "")).strip().upper()
    if not SUPPORT_CODE_PATTERN.fullmatch(code):
        raise SetupError("invalid_support_relay", "Сервер поддержки вернул некорректный код подключения.")
    relay_username = str(raw.get("relay_username", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", relay_username):
        raise SetupError("invalid_support_relay", "Сервер поддержки вернул некорректный логин туннеля.")
    bind_host = str(raw.get("bind_host", ""))
    try:
        bind_address = ipaddress.ip_address(bind_host)
    except ValueError as exc:
        raise SetupError("unsafe_support_bind", "Сервер поддержки попытался открыть не закрытый адрес.") from exc
    if not isinstance(bind_address, ipaddress.IPv4Address) or not bind_address.is_loopback:
        raise SetupError("unsafe_support_bind", "Сервер поддержки попытался открыть не закрытый адрес.")
    revoke_token = str(raw.get("revoke_token", ""))
    if not re.fullmatch(r"[A-Za-z0-9._~-]{24,256}", revoke_token):
        raise SetupError("invalid_support_relay", "Сервер поддержки вернул некорректный ключ отключения.")
    return {
        "session_id": _validate_support_session_id(str(raw.get("session_id", ""))),
        "code": code,
        "expires_at": expires_at,
        "relay_host": _validate_public_hostname(str(raw.get("relay_host", "")), field="relay_host"),
        "relay_port": _validate_port(raw.get("relay_port"), field="relay_port"),
        "relay_username": relay_username,
        "bind_host": bind_host,
        "bind_port": _validate_port(raw.get("bind_port"), field="bind_port"),
        "support_server": _validate_public_hostname(str(raw.get("support_server", "")), field="support_server"),
        "support_port": _validate_port(raw.get("support_port"), field="support_port"),
        "support_public_key": validate_support_public_key(str(raw.get("support_public_key", ""))),
        "revoke_token": revoke_token,
    }


class SupportSessionManager:
    def __init__(
        self,
        config: SupportRelayConfig | None = None,
        *,
        relay_client: RelayClient | None = None,
        tunnel_factory: Callable[..., Tunnel] = ReverseSshTunnel,
        install_key: Callable[..., None] = install_temporary_support_key,
        remove_key: Callable[..., None] = remove_temporary_support_key,
        timer_factory: Callable[..., Any] = threading.Timer,
        key_factory: Callable[[], paramiko.PKey] = lambda: paramiko.RSAKey.generate(3072),
        now: Callable[[], float] = time.time,
        monitor_interval_seconds: float = 3.0,
    ) -> None:
        self.config = config or load_support_relay_config()
        self.relay_client = relay_client or SupportRelayApiClient(self.config)
        self.tunnel_factory = tunnel_factory
        self.install_key = install_key
        self.remove_key = remove_key
        self.timer_factory = timer_factory
        self.key_factory = key_factory
        self.now = now
        self.monitor_interval_seconds = monitor_interval_seconds
        self.lock = threading.Lock()
        self.active: dict[str, Any] | None = None
        self.starting = False

    def public_status(self) -> dict[str, Any]:
        with self.lock:
            active = self.active
            starting = self.starting
        if not self.config.enabled:
            return {
                "status": "unavailable",
                "available": False,
                "message": "Сервер временной поддержки ещё не подключён к этой сборке.",
            }
        if starting:
            return {"status": "starting", "available": True, "duration_seconds": SUPPORT_DURATION_SECONDS}
        if not active:
            return {"status": "inactive", "available": True, "duration_seconds": SUPPORT_DURATION_SECONDS}
        lease = active["lease"]
        return {
            "status": "active",
            "available": True,
            "code": lease["code"],
            "server": lease["support_server"],
            "port": lease["support_port"],
            "router_username": active["router_username"],
            "expires_at": lease["expires_at"],
        }

    def start(self, spec: ConnectionSpec, fingerprint: str, *, router_username: str) -> dict[str, Any]:
        if not self.config.enabled:
            raise SetupError("support_relay_unavailable", "Сервер временной поддержки ещё не подключён к этой сборке.")
        with self.lock:
            if self.active or self.starting:
                raise SetupError("support_already_active", "Временная поддержка уже включена.")
            self.starting = True

        lease: dict[str, Any] | None = None
        tunnel: Tunnel | None = None
        key_installed = False
        client_key = self.key_factory()
        try:
            public_key = f"{client_key.get_name()} {client_key.get_base64()} KatoVPN-Router-Control"
            raw_lease = self.relay_client.create_session(public_key, duration_seconds=SUPPORT_DURATION_SECONDS)
            lease = _normalize_lease(raw_lease, now=int(self.now()))
            self.install_key(spec, fingerprint, lease["support_public_key"], lease["session_id"], lease["expires_at"])
            key_installed = True
            tunnel = self.tunnel_factory(config=self.config, lease=lease, client_key=client_key, router_spec=spec)
            tunnel.start()
            timer = self.timer_factory(max(1, lease["expires_at"] - self.now()), self._expire)
            timer.daemon = True
            timer.start()
            monitor_stop = threading.Event()
            with self.lock:
                self.active = {
                    "lease": lease,
                    "tunnel": tunnel,
                    "timer": timer,
                    "spec": spec,
                    "fingerprint": fingerprint,
                    "router_username": router_username,
                    "monitor_stop": monitor_stop,
                }
                self.starting = False
            threading.Thread(
                target=self._monitor_tunnel,
                args=(lease["session_id"], monitor_stop),
                name="kato-support-monitor",
                daemon=True,
            ).start()
            return self.public_status()
        except SetupError:
            if tunnel is not None:
                tunnel.close()
            if lease is not None and key_installed:
                try:
                    self.remove_key(spec, fingerprint, lease["session_id"])
                except Exception:
                    pass
            if lease is not None:
                try:
                    self.relay_client.revoke_session(lease["session_id"], lease["revoke_token"])
                except Exception:
                    pass
            raise
        except Exception as exc:
            if tunnel is not None:
                tunnel.close()
            if lease is not None and key_installed:
                try:
                    self.remove_key(spec, fingerprint, lease["session_id"])
                except Exception:
                    pass
            if lease is not None:
                try:
                    self.relay_client.revoke_session(lease["session_id"], lease["revoke_token"])
                except Exception:
                    pass
            raise SetupError("support_start_failed", "Не удалось безопасно включить временную поддержку.") from exc
        finally:
            with self.lock:
                self.starting = False

    def _expire(self) -> None:
        self.stop(reason="expired")

    def _monitor_tunnel(self, session_id: str, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.monitor_interval_seconds):
            with self.lock:
                active = self.active
            if not active or active["lease"]["session_id"] != session_id:
                return
            try:
                tunnel_active = active["tunnel"].is_active()
            except Exception:
                tunnel_active = False
            if not tunnel_active:
                self.stop(reason="relay_disconnected")
                return

    def stop(self, *, reason: str = "manual") -> dict[str, Any]:
        del reason
        with self.lock:
            active = self.active
            self.active = None
        if not active:
            return self.public_status()
        warnings: list[str] = []
        active["monitor_stop"].set()
        try:
            active["timer"].cancel()
        except Exception:
            pass
        try:
            active["tunnel"].close()
        except Exception:
            warnings.append("Туннель закрылся без подтверждения приложения.")
        try:
            self.remove_key(active["spec"], active["fingerprint"], active["lease"]["session_id"])
        except Exception:
            warnings.append("Ключ удалит независимый таймер роутера не позднее окончания часа.")
        try:
            self.relay_client.revoke_session(active["lease"]["session_id"], active["lease"]["revoke_token"])
        except Exception:
            warnings.append("Сервер закроет сессию автоматически по сроку действия.")
        result = self.public_status()
        if warnings:
            result["warnings"] = warnings
        return result

    def shutdown(self) -> None:
        self.stop(reason="application_exit")
