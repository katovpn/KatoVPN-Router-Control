from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import re
import secrets
import threading
import time
import urllib.parse
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from .core import (
    PROFILE_NAME,
    USER_AGENT,
    ConnectionSpec,
    SetupError,
    change_lan_ip,
    change_router_password,
    change_wifi_configuration,
    collect_router_logs,
    configure_router,
    create_nikki_backup,
    delete_nikki_backup,
    fetch_and_validate_subscription,
    install_adblock,
    preflight_router,
    replace_router_subscription,
    resource_root,
    restore_router_backup,
    update_router_components,
    validate_inputs,
)
from .control import inspect_router
from .support import SupportSessionManager


APP_VERSION = "0.4.2-preview"
MAX_REQUEST_BYTES = 16 * 1024
PREFLIGHT_TTL_SECONDS = 10 * 60
CLIENT_EXIT_GRACE_SECONDS = 4.0
CLIENT_STREAM_INTERVAL_SECONDS = 1.0
STARTUP_TIMEOUT_SECONDS = 2 * 60
LIFECYCLE_POLL_SECONDS = 0.25


@dataclass
class Job:
    id: str
    status: str = "queued"
    steps: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def progress(self, step: str, state: str, message: str) -> None:
        now = time.time()
        with self.lock:
            current = next((item for item in self.steps if item["id"] == step), None)
            if current is None:
                current = {"id": step, "state": state, "message": message, "updated_at": now}
                self.steps.append(current)
            else:
                current.update({"state": state, "message": message, "updated_at": now})
            self.updated_at = now

    def public(self) -> dict[str, Any]:
        with self.lock:
            return {
                "id": self.id,
                "status": self.status,
                "steps": [dict(item) for item in self.steps],
                "result": dict(self.result) if self.result else None,
                "error": dict(self.error) if self.error else None,
                "updated_at": self.updated_at,
            }


class AppState:
    def __init__(
        self,
        *,
        client_exit_grace_seconds: float = CLIENT_EXIT_GRACE_SECONDS,
        startup_timeout_seconds: float = STARTUP_TIMEOUT_SECONDS,
        lifecycle_poll_seconds: float = LIFECYCLE_POLL_SECONDS,
        support_manager: Any | None = None,
    ) -> None:
        self.token = secrets.token_urlsafe(32)
        self.jobs: dict[str, Job] = {}
        self.preflights: dict[str, dict[str, Any]] = {}
        self.router_session: dict[str, Any] | None = None
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None
        self.clients: set[str] = set()
        self.client_exit_grace_seconds = client_exit_grace_seconds
        self.startup_timeout_seconds = startup_timeout_seconds
        self.lifecycle_poll_seconds = lifecycle_poll_seconds
        self.lifecycle_started_at = time.monotonic()
        self.last_client_left_at: float | None = None
        self.client_seen = False
        self.shutdown_requested = False
        self.shutdown_when_idle = False
        self.lifecycle_monitor_started = False
        self.support_manager = support_manager or SupportSessionManager()

    @staticmethod
    def subscription_hash(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def save_router_session(self, spec: Any, fingerprint: str, dashboard: Mapping[str, Any]) -> None:
        """Keep router credentials in process memory only for the active app session."""
        with self.lock:
            staged_url = ""
            if self.router_session and secrets.compare_digest(str(self.router_session.get("fingerprint", "")), fingerprint):
                staged_url = str(self.router_session.get("staged_subscription_url", ""))
            public_dashboard = dict(dashboard)
            subscription = dict(public_dashboard.get("subscription", {})) if isinstance(public_dashboard.get("subscription"), Mapping) else {}
            if staged_url and not subscription.get("configured"):
                subscription.update({"url": staged_url, "staged": True, "state": "not_installed"})
                public_dashboard["subscription"] = subscription
            self.router_session = {
                "spec": spec,
                "fingerprint": fingerprint,
                "dashboard": public_dashboard,
                "staged_subscription_url": staged_url,
                "created_at": time.time(),
            }

    def stage_subscription(self, url: str) -> None:
        with self.lock:
            if not self.router_session:
                raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
            self.router_session["staged_subscription_url"] = url
            dashboard = dict(self.router_session.get("dashboard", {}))
            subscription = dict(dashboard.get("subscription", {})) if isinstance(dashboard.get("subscription"), Mapping) else {}
            subscription.update({"url": url, "configured": False, "staged": True, "state": "not_installed"})
            dashboard["subscription"] = subscription
            self.router_session["dashboard"] = dashboard

    def get_router_session(self) -> dict[str, Any] | None:
        with self.lock:
            return dict(self.router_session) if self.router_session else None

    def public_router_session(self) -> dict[str, Any] | None:
        support = self.support_manager.public_status()
        with self.lock:
            if not self.router_session:
                return None
            spec = self.router_session["spec"]
            return {
                "connected": True,
                "host": spec.host,
                "port": spec.port,
                "username": spec.username,
                "fingerprint": self.router_session["fingerprint"],
                "dashboard": dict(self.router_session["dashboard"]),
                "support": support,
            }

    def clear_router_session(self) -> None:
        self.support_manager.stop(reason="router_logout")
        with self.lock:
            self.router_session = None

    def save_preflight(self, spec: Any, report: Mapping[str, Any]) -> str:
        preflight_id = uuid.uuid4().hex
        record = {
            "host": spec.host,
            "port": spec.port,
            "username": spec.username,
            "subscription_hash": self.subscription_hash(spec.subscription_url),
            "fingerprint": report["fingerprint"],
            "compatible": bool(report["compatible"]),
            "available_updates": {
                "nikki": bool(report.get("updates", {}).get("nikki", {}).get("can_update")),
                "mihomo": bool(report.get("updates", {}).get("mihomo", {}).get("can_update")),
            },
            "expires_at": time.time() + PREFLIGHT_TTL_SECONDS,
        }
        with self.lock:
            self.preflights[preflight_id] = record
        return preflight_id

    def consume_preflight(self, preflight_id: str, spec: Any, fingerprint: str) -> dict[str, Any]:
        with self.lock:
            record = self.preflights.get(preflight_id)
        if not record or record["expires_at"] < time.time():
            raise SetupError("preflight_expired", "Проверка устарела. Проверьте роутер ещё раз.")
        expected = (
            record["host"],
            record["port"],
            record["username"],
            record["subscription_hash"],
            record["fingerprint"],
        )
        actual = (
            spec.host,
            spec.port,
            spec.username,
            self.subscription_hash(spec.subscription_url),
            fingerprint,
        )
        if expected != actual:
            raise SetupError("preflight_mismatch", "Данные изменились после проверки. Выполните проверку заново.")
        if not record["compatible"]:
            raise SetupError("router_incompatible", "Проверка обнаружила блокирующие несовместимости.")
        return record

    def create_job(self) -> Job:
        job = Job(id=uuid.uuid4().hex)
        with self.lock:
            self.jobs[job.id] = job
        return job

    def start_lifecycle_monitor(self) -> None:
        with self.lock:
            if self.lifecycle_monitor_started:
                return
            self.lifecycle_monitor_started = True
            self.lifecycle_started_at = time.monotonic()
        threading.Thread(target=self._lifecycle_loop, name="kato-browser-lifecycle", daemon=True).start()

    def client_connected(self, client_id: str) -> None:
        with self.lock:
            self.clients.add(client_id)
            self.client_seen = True
            self.last_client_left_at = None

    def client_disconnected(self, client_id: str) -> None:
        with self.lock:
            self.clients.discard(client_id)
            if self.client_seen and not self.clients:
                self.last_client_left_at = time.monotonic()

    def is_shutdown_requested(self) -> bool:
        with self.lock:
            return self.shutdown_requested

    def _has_active_jobs_locked(self) -> bool:
        return any(job.status in {"queued", "running"} for job in self.jobs.values())

    def request_shutdown(self, *, explicit: bool = False) -> bool:
        server: ThreadingHTTPServer | None
        with self.lock:
            if self.shutdown_requested:
                return True
            if self._has_active_jobs_locked():
                if explicit:
                    self.shutdown_when_idle = True
                return False
            if not explicit and self.clients:
                return False
            self.shutdown_requested = True
            server = self.server
        self.support_manager.shutdown()
        if server is not None:
            threading.Thread(target=server.shutdown, name="kato-server-shutdown", daemon=True).start()
        return True

    def _lifecycle_loop(self) -> None:
        while True:
            now = time.monotonic()
            with self.lock:
                if self.shutdown_requested:
                    return
                active_jobs = self._has_active_jobs_locked()
                shutdown_when_idle = self.shutdown_when_idle and not active_jobs
                startup_abandoned = (
                    not self.client_seen
                    and not active_jobs
                    and now - self.lifecycle_started_at >= self.startup_timeout_seconds
                )
                last_client_gone = (
                    self.client_seen
                    and not self.clients
                    and not active_jobs
                    and self.last_client_left_at is not None
                    and now - self.last_client_left_at >= self.client_exit_grace_seconds
                )
            if shutdown_when_idle:
                self.request_shutdown(explicit=True)
                return
            if startup_abandoned or last_client_gone:
                if self.request_shutdown():
                    return
            time.sleep(self.lifecycle_poll_seconds)


class LifecycleHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], state: AppState) -> None:
        self.app_state = state
        super().__init__(server_address, handler)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.app_state.start_lifecycle_monitor()
        super().serve_forever(poll_interval=poll_interval)


def _safe_static_path(path: str) -> tuple[Path, str] | None:
    static_root = (resource_root() / "web").resolve()
    parsed = urllib.parse.urlsplit(path)
    relative = urllib.parse.unquote(parsed.path).lstrip("/") or "index.html"
    if relative == "favicon.ico":
        return None
    candidate = (static_root / relative).resolve()
    try:
        candidate.relative_to(static_root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
    return candidate, content_type


def make_handler(state: AppState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KatoVPNRouterSetup"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            # Request paths can contain the local session token; do not log them.
            del fmt, args

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )

        def _send_json(self, payload: Mapping[str, Any], status: int = HTTPStatus.OK) -> None:
            raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            token = self.headers.get("X-Kato-Token", "")
            origin = self.headers.get("Origin")
            expected_origin = f"http://127.0.0.1:{self.server.server_port}"
            if origin and origin != expected_origin:
                return False
            return secrets.compare_digest(token, state.token)

        def _read_json(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise SetupError("invalid_request", "Некорректный запрос.") from exc
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise SetupError("invalid_request", "Запрос пустой или слишком большой.")
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SetupError("invalid_request", "Некорректный JSON-запрос.") from exc
            if not isinstance(payload, dict):
                raise SetupError("invalid_request", "Ожидался объект JSON.")
            return payload

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/api/session/stream":
                if not self._authorized():
                    self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                    return
                client_id = urllib.parse.parse_qs(parsed.query).get("client_id", [""])[0]
                if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", client_id):
                    self._send_json({"error": {"code": "invalid_client_id", "message": "Некорректная сессия браузера."}}, HTTPStatus.BAD_REQUEST)
                    return
                self.send_response(HTTPStatus.OK)
                self._security_headers()
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Connection", "close")
                self.end_headers()
                state.client_connected(client_id)
                try:
                    while not state.is_shutdown_requested():
                        self.wfile.write(b'{"status":"connected"}\n')
                        self.wfile.flush()
                        time.sleep(CLIENT_STREAM_INTERVAL_SECONDS)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    state.client_disconnected(client_id)
                    self.close_connection = True
                return
            if parsed.path == "/api/meta":
                if not self._authorized():
                    self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                    return
                self._send_json(
                    {
                        "app_version": APP_VERSION,
                        "profile_name": PROFILE_NAME,
                        "user_agent": USER_AGENT,
                        "implemented_modes": [
                            "dashboard", "configure", "update_only", "wifi_changes", "lan_ip",
                            "router_password", "adblock", "backup_management", "log_export", "temporary_support",
                        ],
                        "planned_modes": ["hardware_validated_clean_install", "full_restore"],
                    }
                )
                return
            if parsed.path == "/api/router/session":
                if not self._authorized():
                    self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                    return
                router_session = state.public_router_session()
                self._send_json({"router_session": router_session})
                return
            if parsed.path == "/api/support/status":
                if not self._authorized():
                    self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                    return
                self._send_json({"support": state.support_manager.public_status()})
                return
            if parsed.path.startswith("/api/jobs/"):
                if not self._authorized():
                    self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                    return
                job_id = parsed.path.rsplit("/", 1)[-1]
                with state.lock:
                    job = state.jobs.get(job_id)
                if not job:
                    self._send_json({"error": {"code": "job_not_found", "message": "Операция не найдена."}}, HTTPStatus.NOT_FOUND)
                    return
                self._send_json({"job": job.public()})
                return

            static = _safe_static_path(self.path)
            if static is None:
                if parsed.path == "/favicon.ico":
                    self.send_response(HTTPStatus.NO_CONTENT)
                    self._security_headers()
                    self.end_headers()
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
                return
            path, content_type = static
            raw = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                self._send_json({"error": {"code": "unauthorized", "message": "Сессия недействительна."}}, HTTPStatus.FORBIDDEN)
                return
            try:
                payload = self._read_json()
                if self.path == "/api/router/login":
                    spec = validate_inputs(payload, require_subscription=False)
                    dashboard = inspect_router(spec)
                    state.save_router_session(spec, str(dashboard["fingerprint"]), dashboard)
                    public = state.public_router_session()
                    self._send_json({"router_session": public})
                    return
                if self.path == "/api/router/refresh":
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    spec = saved["spec"]
                    dashboard = inspect_router(spec)
                    if not secrets.compare_digest(str(saved["fingerprint"]), str(dashboard["fingerprint"])):
                        state.clear_router_session()
                        raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Войдите заново и проверьте адрес устройства.")
                    state.save_router_session(spec, str(dashboard["fingerprint"]), dashboard)
                    self._send_json({"router_session": state.public_router_session()})
                    return
                if self.path == "/api/router/logout":
                    state.clear_router_session()
                    self._send_json({"status": "logged_out"})
                    return
                if self.path == "/api/support/start":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите временный доступ поддержки на один час.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    support = state.support_manager.start(
                        saved["spec"],
                        str(saved["fingerprint"]),
                        router_username=saved["spec"].username,
                    )
                    self._send_json({"support": support}, HTTPStatus.CREATED)
                    return
                if self.path == "/api/support/stop":
                    support = state.support_manager.stop(reason="manual")
                    self._send_json({"support": support})
                    return
                if self.path == "/api/router/update-components":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите создание backup и обновление компонентов.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    update_nikki = payload.get("update_nikki") is True
                    update_mihomo = payload.get("update_mihomo") is True
                    if not update_nikki and not update_mihomo:
                        raise SetupError("component_update_required", "Не выбрано ни одного компонента для обновления.")
                    spec = saved["spec"]
                    report = preflight_router(spec, check_subscription=False)
                    if not secrets.compare_digest(str(saved["fingerprint"]), str(report["fingerprint"])):
                        state.clear_router_session()
                        raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Войдите заново.")
                    if not report.get("compatible"):
                        raise SetupError("router_incompatible", "Обновление заблокировано проверкой совместимости.", {"blockers": report.get("blockers", [])})
                    available = report.get("updates", {})
                    if update_nikki and not available.get("nikki", {}).get("can_update"):
                        raise SetupError("nikki_update_unavailable", "Совместимое обновление Nikki больше не доступно.")
                    if update_mihomo and not available.get("mihomo", {}).get("can_update"):
                        raise SetupError("mihomo_update_unavailable", "Совместимое обновление Mihomo Core больше не доступно.")
                    job = state.create_job()
                    self._start_update_job(job, spec, str(saved["fingerprint"]), update_nikki, update_mihomo)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/configure-subscription":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите создание backup и изменение подписки.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    current = saved["spec"]
                    spec = validate_inputs(
                        {
                            "host": current.host,
                            "port": current.port,
                            "username": current.username,
                            "password": current.password,
                            "subscription_url": payload.get("subscription_url", ""),
                        },
                        require_subscription=True,
                    )
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    components = dashboard.get("components") if isinstance(dashboard.get("components"), Mapping) else {}
                    nikki_ready = bool((components.get("nikki") or {}).get("installed")) if isinstance(components.get("nikki"), Mapping) else False
                    mihomo_ready = bool((components.get("mihomo") or {}).get("installed")) if isinstance(components.get("mihomo"), Mapping) else False
                    if not (nikki_ready and mihomo_ready):
                        fetch_and_validate_subscription(spec.subscription_url)
                        state.stage_subscription(spec.subscription_url)
                        self._send_json({"status": "staged", "router_session": state.public_router_session()})
                        return
                    report = preflight_router(spec, check_subscription=True)
                    if not secrets.compare_digest(str(saved["fingerprint"]), str(report["fingerprint"])):
                        state.clear_router_session()
                        raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Войдите заново.")
                    if not report.get("compatible"):
                        raise SetupError("router_incompatible", "Настройка заблокирована проверкой совместимости.", {"blockers": report.get("blockers", [])})
                    job = state.create_job()
                    subscription = dashboard.get("subscription") if isinstance(dashboard.get("subscription"), Mapping) else {}
                    if subscription.get("configured"):
                        self._start_subscription_job(job, spec, str(saved["fingerprint"]))
                    else:
                        self._start_apply_job(job, spec, str(saved["fingerprint"]), False, False)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/wifi":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите изменение Wi‑Fi и двухминутный автоматический откат.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    safety = dashboard.get("safety") if isinstance(dashboard.get("safety"), Mapping) else {}
                    if not safety.get("wifi_changes_enabled"):
                        raise SetupError("wifi_change_unavailable", "Роутер не подтвердил безопасный таймер отката Wi‑Fi.")
                    action = str(payload.get("action", "change_password"))
                    if action not in {"change_password", "create"}:
                        raise SetupError("invalid_wifi_action", "Неизвестная операция Wi‑Fi.")
                    spec = saved["spec"]
                    fingerprint = str(saved["fingerprint"])
                    radio = str(payload.get("radio", ""))
                    password = str(payload.get("password", ""))
                    country = str(payload.get("country") or (dashboard.get("lan") or {}).get("recommended_country") or "RU")
                    section = str(payload.get("section", "")) if action == "change_password" else None
                    ssid = str(payload.get("ssid", "")) if action == "create" else None
                    job = state.create_job()
                    self._start_callable_job(
                        job,
                        "wifi",
                        lambda: change_wifi_configuration(
                            spec,
                            fingerprint,
                            radio=radio,
                            section=section,
                            ssid=ssid,
                            password=password,
                            country=country,
                            progress=job.progress,
                        ),
                    )
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/lan-ip":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите смену локального IP и автоматический откат.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    safety = dashboard.get("safety") if isinstance(dashboard.get("safety"), Mapping) else {}
                    if not safety.get("lan_changes_enabled"):
                        raise SetupError("lan_change_unavailable", "Текущую LAN-сеть нельзя безопасно изменить.")
                    spec = saved["spec"]
                    fingerprint = str(saved["fingerprint"])
                    new_ip = str(payload.get("new_ip", ""))
                    job = state.create_job()

                    def change_lan() -> dict[str, Any]:
                        result = change_lan_ip(spec, fingerprint, new_ip, progress=job.progress)
                        new_spec = ConnectionSpec(result["new_ip"], spec.username, spec.password, spec.subscription_url, spec.port)
                        refreshed = inspect_router(new_spec)
                        if not secrets.compare_digest(fingerprint, str(refreshed["fingerprint"])):
                            raise SetupError("router_fingerprint_changed", "После смены адреса получен другой SSH-ключ роутера.")
                        state.save_router_session(new_spec, fingerprint, refreshed)
                        return result

                    self._start_callable_job(job, "lan", change_lan)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/change-password":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите смену пароля роутера и автоматический откат.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    safety = dashboard.get("safety") if isinstance(dashboard.get("safety"), Mapping) else {}
                    if not safety.get("password_change_enabled"):
                        raise SetupError("router_password_change_unavailable", "Роутер не подтвердил безопасную смену пароля.")
                    new_password = str(payload.get("new_password", ""))
                    confirmation = str(payload.get("confirm_password", ""))
                    if new_password != confirmation:
                        raise SetupError("router_password_mismatch", "Новый пароль и подтверждение не совпадают.")
                    spec = saved["spec"]
                    fingerprint = str(saved["fingerprint"])
                    job = state.create_job()

                    def change_password() -> dict[str, Any]:
                        result = change_router_password(
                            spec,
                            fingerprint,
                            new_password,
                            progress=job.progress,
                        )
                        new_spec = ConnectionSpec(spec.host, spec.username, new_password, spec.subscription_url, spec.port)
                        state.save_router_session(new_spec, fingerprint, dashboard)
                        return result

                    self._start_callable_job(job, "router-password", change_password)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/install-adblock":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите установку официальных пакетов AdBlock.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    safety = dashboard.get("safety") if isinstance(dashboard.get("safety"), Mapping) else {}
                    if not safety.get("adblock_install_enabled"):
                        raise SetupError("adblock_install_unavailable", "AdBlock недоступен для ресурсов или текущего состояния этого роутера.")
                    job = state.create_job()
                    self._start_callable_job(
                        job,
                        "adblock",
                        lambda: install_adblock(saved["spec"], str(saved["fingerprint"]), progress=job.progress),
                    )
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/create-backup":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите создание резервной копии настроек VPN.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    job = state.create_job()
                    self._start_callable_job(
                        job,
                        "backup",
                        lambda: create_nikki_backup(saved["spec"], str(saved["fingerprint"]), progress=job.progress),
                    )
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/delete-backup":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите безвозвратное удаление выбранной резервной копии.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    backup_id = str(payload.get("backup_id", ""))
                    job = state.create_job()
                    self._start_callable_job(
                        job,
                        "backup-delete",
                        lambda: delete_nikki_backup(saved["spec"], str(saved["fingerprint"]), backup_id, progress=job.progress),
                    )
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/restore-backup":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите восстановление выбранной резервной копии.")
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    job = state.create_job()
                    self._start_restore_job(job, saved["spec"], str(saved["fingerprint"]), str(payload.get("backup_id", "")))
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/router/export-logs":
                    saved = state.get_router_session()
                    if not saved:
                        raise SetupError("router_session_required", "Сначала подключитесь к роутеру.")
                    dashboard = saved.get("dashboard") if isinstance(saved.get("dashboard"), Mapping) else {}
                    safety = dashboard.get("safety") if isinstance(dashboard.get("safety"), Mapping) else {}
                    if not safety.get("log_export_enabled"):
                        raise SetupError("log_export_unavailable", "Журналы Nikki недоступны, пока модуль VPN не установлен.")
                    result = collect_router_logs(
                        saved["spec"],
                        str(saved["fingerprint"]),
                        str(payload.get("kind", "connections")),
                        source=str(payload.get("source", "all")),
                        lines=payload.get("lines", 500),
                    )
                    self._send_json(result)
                    return
                if self.path == "/api/preflight":
                    mode = str(payload.get("mode", "configure"))
                    if mode not in {"configure", "update"}:
                        raise SetupError("mode_not_available", "Выбранный режим пока недоступен.")
                    spec = validate_inputs(payload, require_subscription=mode == "configure")
                    report = preflight_router(spec, check_subscription=mode == "configure")
                    preflight_id = state.save_preflight(spec, report)
                    self._send_json({"preflight_id": preflight_id, "report": report})
                    return
                if self.path == "/api/apply":
                    if payload.get("mode") != "configure":
                        raise SetupError("mode_not_available", "В V1 доступен только режим настройки Nikki.")
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите роутер и создание backup.")
                    spec = validate_inputs(payload, require_subscription=payload.get("mode") == "configure")
                    fingerprint = str(payload.get("fingerprint", ""))
                    preflight_id = str(payload.get("preflight_id", ""))
                    record = state.consume_preflight(preflight_id, spec, fingerprint)
                    for field in ("update_nikki", "update_mihomo"):
                        if field in payload and not isinstance(payload[field], bool):
                            raise SetupError("invalid_update_option", "Некорректный выбор обновления.")
                    update_nikki = payload.get("update_nikki") is True
                    update_mihomo = payload.get("update_mihomo") is True
                    available_updates = record.get("available_updates", {})
                    if update_nikki and not available_updates.get("nikki"):
                        raise SetupError("nikki_update_unavailable", "Выбранное обновление Nikki больше недоступно. Повторите проверку.")
                    if update_mihomo and not available_updates.get("mihomo"):
                        raise SetupError("mihomo_update_unavailable", "Выбранное обновление Mihomo Core больше недоступно. Повторите проверку.")
                    job = state.create_job()
                    self._start_apply_job(job, spec, fingerprint, update_nikki, update_mihomo)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/update-components":
                    if payload.get("mode") != "update":
                        raise SetupError("mode_not_available", "Для этой операции выберите режим «Только обновить».")
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите роутер и создание backup.")
                    spec = validate_inputs(payload, require_subscription=False)
                    fingerprint = str(payload.get("fingerprint", ""))
                    preflight_id = str(payload.get("preflight_id", ""))
                    record = state.consume_preflight(preflight_id, spec, fingerprint)
                    for field in ("update_nikki", "update_mihomo"):
                        if field in payload and not isinstance(payload[field], bool):
                            raise SetupError("invalid_update_option", "Некорректный выбор обновления.")
                    update_nikki = payload.get("update_nikki") is True
                    update_mihomo = payload.get("update_mihomo") is True
                    if not update_nikki and not update_mihomo:
                        raise SetupError("component_update_required", "Выберите хотя бы один компонент для обновления.")
                    available_updates = record.get("available_updates", {})
                    if update_nikki and not available_updates.get("nikki"):
                        raise SetupError("nikki_update_unavailable", "Обновление Nikki больше недоступно. Повторите проверку.")
                    if update_mihomo and not available_updates.get("mihomo"):
                        raise SetupError("mihomo_update_unavailable", "Обновление Mihomo Core больше недоступно. Повторите проверку.")
                    job = state.create_job()
                    self._start_update_job(job, spec, fingerprint, update_nikki, update_mihomo)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/restore":
                    if payload.get("confirmed") is not True:
                        raise SetupError("confirmation_required", "Подтвердите восстановление выбранного backup.")
                    spec = validate_inputs(payload, require_subscription=payload.get("mode") == "configure")
                    fingerprint = str(payload.get("fingerprint", ""))
                    preflight_id = str(payload.get("preflight_id", ""))
                    backup_id = str(payload.get("backup_id", ""))
                    state.consume_preflight(preflight_id, spec, fingerprint)
                    job = state.create_job()
                    self._start_restore_job(job, spec, fingerprint, backup_id)
                    self._send_json({"job_id": job.id}, HTTPStatus.ACCEPTED)
                    return
                if self.path == "/api/session/close":
                    client_id = str(payload.get("client_id", ""))
                    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", client_id):
                        raise SetupError("invalid_client_id", "Некорректная сессия браузера.")
                    state.client_disconnected(client_id)
                    self._send_json({"status": "closed"})
                    return
                if self.path == "/api/shutdown":
                    self._send_json({"status": "shutting_down"})
                    state.request_shutdown(explicit=True)
                    return
                raise SetupError("not_found", "Неизвестная операция.")
            except SetupError as exc:
                self._send_json({"error": exc.as_dict()}, HTTPStatus.BAD_REQUEST)

        @staticmethod
        def _start_callable_job(job: Job, thread_name: str, action: Callable[[], dict[str, Any]]) -> None:
            def runner() -> None:
                job.status = "running"
                job.updated_at = time.time()
                try:
                    job.result = action()
                    job.status = "success"
                except SetupError as exc:
                    job.error = exc.as_dict()
                    job.status = "failed"
                except Exception:
                    job.error = {"code": "unexpected", "message": "Операция остановлена из-за непредвиденной ошибки.", "details": {}}
                    job.status = "failed"
                finally:
                    job.updated_at = time.time()

            threading.Thread(target=runner, name=f"kato-{thread_name}-{job.id[:8]}", daemon=True).start()

        @staticmethod
        def _start_apply_job(
            job: Job,
            spec: Any,
            fingerprint: str,
            update_nikki: bool,
            update_mihomo: bool,
        ) -> None:
            local_spec = spec

            def runner() -> None:
                job.status = "running"
                job.updated_at = time.time()
                try:
                    job.result = configure_router(
                        local_spec,
                        fingerprint,
                        progress=job.progress,
                        update_nikki=update_nikki,
                        update_mihomo=update_mihomo,
                    )
                    job.status = "success"
                except SetupError as exc:
                    job.error = exc.as_dict()
                    job.status = "failed"
                except Exception:
                    job.error = {"code": "unexpected", "message": "Операция остановлена из-за непредвиденной ошибки.", "details": {}}
                    job.status = "failed"
                finally:
                    job.updated_at = time.time()

            threading.Thread(target=runner, name=f"nikki-setup-{job.id[:8]}", daemon=True).start()

        @staticmethod
        def _start_restore_job(job: Job, spec: Any, fingerprint: str, backup_id: str) -> None:
            local_spec = spec

            def runner() -> None:
                job.status = "running"
                job.updated_at = time.time()
                try:
                    job.result = restore_router_backup(
                        local_spec,
                        fingerprint,
                        backup_id,
                        progress=job.progress,
                    )
                    job.status = "success"
                except SetupError as exc:
                    job.error = exc.as_dict()
                    job.status = "failed"
                except Exception:
                    job.error = {"code": "unexpected", "message": "Операция остановлена из-за непредвиденной ошибки.", "details": {}}
                    job.status = "failed"
                finally:
                    job.updated_at = time.time()

            threading.Thread(target=runner, name=f"nikki-restore-{job.id[:8]}", daemon=True).start()

        @staticmethod
        def _start_subscription_job(job: Job, spec: Any, fingerprint: str) -> None:
            local_spec = spec

            def runner() -> None:
                job.status = "running"
                job.updated_at = time.time()
                try:
                    job.result = replace_router_subscription(
                        local_spec,
                        fingerprint,
                        progress=job.progress,
                    )
                    job.status = "success"
                except SetupError as exc:
                    job.error = exc.as_dict()
                    job.status = "failed"
                except Exception:
                    job.error = {
                        "code": "unexpected",
                        "message": "Смена ссылки остановлена из-за непредвиденной ошибки.",
                        "details": {},
                    }
                    job.status = "failed"
                finally:
                    job.updated_at = time.time()

            threading.Thread(target=runner, name=f"nikki-subscription-{job.id[:8]}", daemon=True).start()

        @staticmethod
        def _start_update_job(
            job: Job,
            spec: Any,
            fingerprint: str,
            update_nikki: bool,
            update_mihomo: bool,
        ) -> None:
            local_spec = spec

            def runner() -> None:
                job.status = "running"
                job.updated_at = time.time()
                try:
                    job.result = update_router_components(
                        local_spec,
                        fingerprint,
                        progress=job.progress,
                        update_nikki=update_nikki,
                        update_mihomo=update_mihomo,
                    )
                    job.status = "success"
                except SetupError as exc:
                    job.error = exc.as_dict()
                    job.status = "failed"
                except Exception:
                    job.error = {"code": "unexpected", "message": "Обновление остановлено из-за непредвиденной ошибки.", "details": {}}
                    job.status = "failed"
                finally:
                    job.updated_at = time.time()

            threading.Thread(target=runner, name=f"nikki-update-{job.id[:8]}", daemon=True).start()

    return Handler


def run_server(*, port: int = 0, open_browser: bool = True, session_token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    state = AppState()
    if session_token is not None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", session_token):
            raise SetupError("invalid_session_token", "Локальный session token имеет неверный формат.")
        state.token = session_token
    server = LifecycleHTTPServer(("127.0.0.1", port), make_handler(state), state)
    state.server = server
    actual_port = int(server.server_address[1])
    url = f"http://127.0.0.1:{actual_port}/?token={urllib.parse.quote(state.token)}"
    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url, new=1)).start()
    return server, url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KatoVPN Nikki Router Setup")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--session-token", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    server, url = run_server(
        port=args.port,
        open_browser=not args.no_browser and not args.smoke_test,
        session_token=args.session_token,
    )
    if args.smoke_test:
        parsed = urllib.parse.urlsplit(url)
        server.server_close()
        print(f"{parsed.scheme}://{parsed.netloc}/")
        return 0
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
