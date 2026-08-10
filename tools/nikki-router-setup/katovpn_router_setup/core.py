from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import socket
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

import paramiko
import requests
import yaml


PROFILE_NAME = "KatoVPN - Router Russia"
USER_AGENT = "katorouter-ru"
REQUIRED_POLICY_TARGETS = {"DIRECT", "⚡️ Авто", "🇳🇱 Нидерланды"}
MAX_SUBSCRIPTION_BYTES = 5 * 1024 * 1024
MIN_FREE_OVERLAY_KB = 512
MIHOMO_ADOPTION_MIN_FREE_KB = 48 * 1024
VPN_INSTALL_MIN_RAM_KB = 200 * 1024
VPN_INSTALL_MIN_OVERLAY_KB = 64 * 1024
VPN_INSTALL_DEPENDENCIES = (
    "ca-bundle",
    "curl",
    "yq",
    "firewall4",
    "ip-full",
    "kmod-inet-diag",
    "kmod-nft-socket",
    "kmod-nft-tproxy",
    "kmod-tun",
    "kmod-dummy",
)
NIKKI_RELEASE_API = "https://api.github.com/repos/nikkinikki-org/OpenWrt-nikki/releases/latest"
NIKKI_RELEASE_PAGE = "https://github.com/nikkinikki-org/OpenWrt-nikki/releases/latest"
NIKKI_FEED_BASE = "https://nikkinikki.pages.dev"
BACKUP_ROOT = "/root/katovpn-nikki-backups"
BACKUP_ID_PATTERN = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}(?:-[0-9a-f]{4})?$")
ROUTER_ROLLBACK_ROOT = "/root/katovpn-router-rollbacks"
NETWORK_ROLLBACK_SECONDS = 120
ADBLOCK_MIN_RAM_KB = 448 * 1024
ADBLOCK_PACKAGES = ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru")
MAX_DIAGNOSTIC_BYTES = 2 * 1024 * 1024


class SetupError(RuntimeError):
    """An error whose message is safe to show in the local UI."""

    def __init__(self, code: str, message: str, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


@dataclass(frozen=True)
class ConnectionSpec:
    host: str
    username: str
    password: str
    subscription_url: str
    port: int = 22


class ProgressCallback(Protocol):
    def __call__(self, step: str, state: str, message: str) -> None: ...


def _noop_progress(step: str, state: str, message: str) -> None:
    del step, state, message


def resource_root() -> Path:
    import sys

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def profile_template_path() -> Path:
    return resource_root() / "profile" / "nikki-router-russia-v2.uci"


def redact_subscription_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme and parsed.hostname:
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://{parsed.hostname}{port}/…"
    except (ValueError, TypeError):
        pass
    return "[скрыто]"


def _validate_host(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 253 or "://" in value or any(ch.isspace() for ch in value):
        raise SetupError("invalid_host", "Укажите IP-адрес или имя роутера без http://.")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not labels or any(not label_pattern.fullmatch(label) for label in labels):
        raise SetupError("invalid_host", "IP-адрес или имя роутера имеет неверный формат.")
    return value


def _validate_username(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", value):
        raise SetupError("invalid_username", "Логин может содержать буквы, цифры, точку, дефис и подчёркивание.")
    return value


def _validate_subscription_url(value: str) -> str:
    value = value.strip()
    if len(value) > 4096 or any(ord(ch) < 32 for ch in value):
        raise SetupError("invalid_subscription_url", "Ссылка подписки имеет неверный формат.")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise SetupError("invalid_subscription_url", "Ссылка подписки имеет неверный формат.") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SetupError("invalid_subscription_url", "Нужна HTTPS-ссылка подписки без логина и пароля в адресе.")
    return value


def validate_inputs(payload: Mapping[str, Any], *, require_subscription: bool = True) -> ConnectionSpec:
    host = _validate_host(str(payload.get("host", "")))
    username = _validate_username(str(payload.get("username", "")))
    password = str(payload.get("password", ""))
    if not password or len(password) > 256 or any(ch in "\r\n\0" for ch in password):
        raise SetupError("invalid_password", "Введите пароль роутера.")
    raw_subscription_url = str(payload.get("subscription_url", "")).strip()
    subscription_url = _validate_subscription_url(raw_subscription_url) if require_subscription else ""
    try:
        port = int(payload.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise SetupError("invalid_port", "SSH-порт должен быть числом.") from exc
    if not 1 <= port <= 65535:
        raise SetupError("invalid_port", "SSH-порт должен быть от 1 до 65535.")
    return ConnectionSpec(host=host, username=username, password=password, subscription_url=subscription_url, port=port)


def validate_wifi_password(value: str) -> str:
    """Validate an OpenWrt WPA2/WPA3 passphrase without normalizing it."""
    value = str(value)
    if not 8 <= len(value) <= 63 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SetupError("invalid_wifi_password", "Пароль Wi‑Fi должен содержать от 8 до 63 печатных символов.")
    return value


def validate_router_password(value: str) -> str:
    """Validate a router login password without normalizing or logging it."""
    value = str(value)
    if not 8 <= len(value) <= 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SetupError("invalid_router_password", "Новый пароль роутера должен содержать от 8 до 128 печатных символов.")
    return value


def validate_wifi_ssid(value: str) -> str:
    value = str(value).strip()
    if not value or len(value.encode("utf-8")) > 32 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SetupError("invalid_wifi_ssid", "Название Wi‑Fi должно занимать от 1 до 32 байт и не содержать служебные символы.")
    return value


def validate_lan_ip(value: str, netmask: str) -> str:
    try:
        address = ipaddress.IPv4Address(str(value).strip())
        network = ipaddress.IPv4Network(f"{address}/{str(netmask).strip()}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise SetupError("invalid_lan_ip", "Укажите корректный локальный IPv4-адрес роутера.") from exc
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(address in item for item in private_ranges) or address in {network.network_address, network.broadcast_address}:
        raise SetupError("invalid_lan_ip", "Нужен частный адрес хоста, а не публичный, сетевой или broadcast-адрес.")
    return str(address)


def _validate_uci_section(value: str, *, label: str) -> str:
    value = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", value):
        raise SetupError("invalid_network_target", f"Некорректный идентификатор {label}.")
    return value


def _validate_operation_id(value: str) -> str:
    if not BACKUP_ID_PATTERN.fullmatch(str(value)):
        raise SetupError("invalid_operation_id", "Некорректный идентификатор сетевой операции.")
    return str(value)


def build_wifi_rollback_command(operation_id: str) -> str:
    operation_id = _validate_operation_id(operation_id)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    marker = f"{rollback_dir}/confirmed"
    script = f"{rollback_dir}/rollback-wifi.sh"
    pidfile = f"{rollback_dir}/rollback.pid"
    return (
        f"mkdir -p {shlex.quote(rollback_dir)}; cp -f /etc/config/wireless {shlex.quote(rollback_dir + '/wireless')}; "
        f"cat > {shlex.quote(script)} <<'KATO_ROLLBACK'\n"
        "#!/bin/sh\n"
        f"sleep {NETWORK_ROLLBACK_SECONDS}\n"
        f"if [ ! -f {shlex.quote(marker)} ]; then\n"
        f"  cp -f {shlex.quote(rollback_dir + '/wireless')} /etc/config/wireless\n"
        "  wifi reload >/dev/null 2>&1 || wifi >/dev/null 2>&1\n"
        "fi\n"
        "rm -f /tmp/kato-wifi-key /tmp/kato-wifi-ssid\n"
        f"rm -rf {shlex.quote(rollback_dir)}\n"
        "KATO_ROLLBACK\n"
        f"chmod 700 {shlex.quote(script)}; start-stop-daemon -S -b -m -p {shlex.quote(pidfile)} "
        f"-x /bin/sh -- {shlex.quote(script)}"
    )


def build_wifi_apply_command(
    section: str,
    radio: str,
    country: str,
    operation_id: str,
    *,
    password_changed: bool,
) -> str:
    section = _validate_uci_section(section, label="Wi‑Fi сети")
    radio = _validate_uci_section(radio, label="радиомодуля")
    operation_id = _validate_operation_id(operation_id)
    country = str(country).upper()
    if country not in {"RU", "CN"}:
        raise SetupError("invalid_wifi_country", "Для автоматической настройки поддерживаются коды RU и CN.")
    del operation_id
    password_command = (
        "key=$(cat /tmp/kato-wifi-key); "
        f"uci set wireless.{section}.encryption='sae-mixed'; "
        f"uci set wireless.{section}.key=\"$key\"; "
        if password_changed
        else ""
    )
    return (
        "ssid=$(cat /tmp/kato-wifi-ssid); "
        f"uci set wireless.{section}.device={shlex.quote(radio)}; "
        f"uci set wireless.{section}.mode='ap'; "
        f"uci set wireless.{section}.ssid=\"$ssid\"; "
        + password_command
        + f"uci set wireless.{radio}.disabled='0'; "
        + f"uci set wireless.{radio}.country={shlex.quote(country)}; "
        "uci commit wireless; wifi reload >/dev/null 2>&1 || wifi"
    )


def build_wifi_create_command(radio: str, country: str, operation_id: str) -> str:
    radio = _validate_uci_section(radio, label="радиомодуля")
    operation_id = _validate_operation_id(operation_id)
    country = str(country).upper()
    if country not in {"RU", "CN"}:
        raise SetupError("invalid_wifi_country", "Для автоматической настройки поддерживаются коды RU и CN.")
    section = "kato_wifi_" + re.sub(r"[^0-9a-f]", "", operation_id)[-8:]
    return (
        "key=$(cat /tmp/kato-wifi-key); ssid=$(cat /tmp/kato-wifi-ssid); "
        f"uci set wireless.{section}=wifi-iface; uci set wireless.{section}.device={shlex.quote(radio)}; "
        f"uci set wireless.{section}.mode='ap'; uci set wireless.{section}.network='lan'; "
        f"uci set wireless.{section}.ssid=\"$ssid\"; uci set wireless.{section}.encryption='sae-mixed'; "
        f"uci set wireless.{section}.key=\"$key\"; "
        f"uci set wireless.{radio}.disabled='0'; "
        f"uci set wireless.{radio}.country={shlex.quote(country)}; "
        f"uci commit wireless; wifi reload >/dev/null 2>&1 || wifi; printf '%s' {shlex.quote(section)}"
    )


def build_lan_rollback_command(operation_id: str) -> str:
    operation_id = _validate_operation_id(operation_id)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    marker = f"{rollback_dir}/confirmed"
    script = f"{rollback_dir}/rollback-lan.sh"
    pidfile = f"{rollback_dir}/rollback.pid"
    return (
        f"mkdir -p {shlex.quote(rollback_dir)}; cp -f /etc/config/network {shlex.quote(rollback_dir + '/network')}; "
        f"cat > {shlex.quote(script)} <<'KATO_ROLLBACK'\n"
        "#!/bin/sh\n"
        f"sleep {NETWORK_ROLLBACK_SECONDS}\n"
        f"if [ ! -f {shlex.quote(marker)} ]; then\n"
        f"  cp -f {shlex.quote(rollback_dir + '/network')} /etc/config/network\n"
        "  /etc/init.d/network reload >/dev/null 2>&1\n"
        "fi\n"
        f"rm -rf {shlex.quote(rollback_dir)}\n"
        "KATO_ROLLBACK\n"
        f"chmod 700 {shlex.quote(script)}; start-stop-daemon -S -b -m -p {shlex.quote(pidfile)} "
        f"-x /bin/sh -- {shlex.quote(script)}"
    )


def build_router_password_rollback_command(operation_id: str) -> str:
    operation_id = _validate_operation_id(operation_id)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    marker = f"{rollback_dir}/confirmed"
    script = f"{rollback_dir}/rollback-password.sh"
    pidfile = f"{rollback_dir}/rollback.pid"
    return (
        f"mkdir -p {shlex.quote(rollback_dir)}; chmod 700 {shlex.quote(rollback_dir)}; "
        f"cp -p /etc/shadow {shlex.quote(rollback_dir + '/shadow')}; "
        f"cat > {shlex.quote(script)} <<'KATO_ROLLBACK'\n"
        "#!/bin/sh\n"
        f"sleep {NETWORK_ROLLBACK_SECONDS}\n"
        f"if [ ! -f {shlex.quote(marker)} ]; then\n"
        f"  cp -p {shlex.quote(rollback_dir + '/shadow')} /etc/shadow\n"
        "fi\n"
        "rm -f /tmp/kato-router-password\n"
        f"rm -rf {shlex.quote(rollback_dir)}\n"
        "KATO_ROLLBACK\n"
        f"chmod 700 {shlex.quote(script)}; start-stop-daemon -S -b -m -p {shlex.quote(pidfile)} "
        f"-x /bin/sh -- {shlex.quote(script)}"
    )


def sanitize_diagnostic_text(value: str, *, extra_secrets: list[str] | tuple[str, ...] = ()) -> str:
    text = str(value)[:MAX_DIAGNOSTIC_BYTES]
    for secret in sorted({str(item) for item in extra_secrets if item}, key=len, reverse=True):
        text = text.replace(secret, "[скрыто]")
    text = re.sub(r"(?i)\bAuthorization\s*:\s*[^\r\n]+", "Authorization: [скрыто]", text)
    text = re.sub(r"(?i)https?://[^\s'\"<>]+", "[скрыто]", text)
    sensitive = r"(?:password|passwd|api[_-]?secret|secret|token|authorization|private[_-]?key|uuid|url)"
    text = re.sub(
        rf"(?im)(\b{sensitive}\b\s*[:=]\s*)(?:'[^']*'|\"[^\"]*\"|[^\r\n,}}]+)",
        lambda match: match.group(1) + "[скрыто]",
        text,
    )
    return text


def package_manager_failure_diagnostic(value: str, manager: str) -> str:
    """Return a short, sanitized explanation for a failed package dry run."""
    raw = sanitize_diagnostic_text(value)
    raw = re.sub(r"(?m)^__KATO_(?:PACKAGE|OPKG)_EXIT__=\d+\s*$", "", raw)
    compact = "\n".join(line.strip() for line in raw.splitlines() if line.strip())
    lowered = compact.lower()

    missing: list[str] = []
    if manager == "apk":
        missing.extend(re.findall(r"(?im)^\s*([A-Za-z0-9][A-Za-z0-9+_.-]*)\s*\(no such package\)", compact))
        missing.extend(re.findall(r"(?im)^(?:ERROR:\s*)?unable to select packages?:?\s*([A-Za-z0-9][A-Za-z0-9+_.-]*)?", compact))
    else:
        missing.extend(re.findall(r"(?im)unknown package ['\"]?([A-Za-z0-9][A-Za-z0-9+_.-]*)", compact))
        missing.extend(re.findall(r"(?im)cannot find package\s+([A-Za-z0-9][A-Za-z0-9+_.-]*)", compact))
    missing = sorted({item for item in missing if item})

    if "not enough space" in lowered or "no space left" in lowered or "only have" in lowered:
        return "На системном разделе недостаточно свободного места для выбранных пакетов."
    if any(
        marker in lowered
        for marker in (
            "temporary error",
            "network error",
            "connection timed out",
            "bad address",
            "download error",
            "wgetssl error",
            "unexpected end of file",
            "exited with error 4",
        )
    ):
        return "Роутер не смог загрузить индекс или пакет из репозитория."
    if missing:
        return "Репозитории роутера не предоставили пакеты: " + ", ".join(missing[:8]) + "."
    if any(marker in lowered for marker in ("untrusted signature", "signature verification failed", "public key not found")):
        return "Пакетный менеджер не смог подтвердить подпись репозитория."
    if any(marker in lowered for marker in ("breaks: world[", "conflicts:", "conflicting packages", "solver error")):
        return "Установленный набор пакетов конфликтует с новым VPN-модулем."
    if "unable to select packages" in lowered:
        return "Пакетный менеджер не смог подобрать совместимый комплект зависимостей."
    if not compact:
        return "Пакетный менеджер завершил проверку с ошибкой без пояснения."

    # Package-manager output does not contain the subscription or SSH password,
    # but sanitize it anyway and keep only a small tail suitable for the local UI.
    tail = compact.splitlines()[-6:]
    summary = " ".join(tail)
    summary = re.sub(r"\s+", " ", summary).strip()
    if len(summary) > 600:
        summary = summary[:597].rstrip() + "…"
    return f"Ответ {manager}: {summary}"


def validate_portable_template(text: str) -> dict[str, Any]:
    forbidden = [
        r"(?im)^\s*config\s+subscription\b",
        r"(?im)^\s*(?:option|list)\s+(?:url|api_secret|password|token|subscription_url)\b",
        r"(?i)(?:vless|vmess|trojan|ss|ssr|hysteria2?)://",
        r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    ]
    for pattern in forbidden:
        if re.search(pattern, text):
            raise SetupError("unsafe_template", "Шаблон содержит данные, которые нельзя переносить.")

    allowed_url_keys = {"ui_url", "nameserver"}
    for match in re.finditer(r"(?im)^\s*(?:option|list)\s+(\S+)\s+'([^']*://[^']*)'\s*$", text):
        key, value = match.groups()
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError as exc:
            raise SetupError("unsafe_template", "В шаблоне обнаружен некорректный URL.") from exc
        if key not in allowed_url_keys or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SetupError("unsafe_template", "В шаблоне обнаружен непереносимый URL.")

    required_lines = {
        "option enabled '0'",
        "option tcp_mode 'redirect'",
        "option udp_mode 'tproxy'",
        "option ipv4_dns_hijack '1'",
        "option ipv6_proxy '0'",
        "option tun_dns_hijack '0'",
        "option tproxy_fw_mark '0x80'",
    }
    missing = sorted(line for line in required_lines if line not in text)
    if missing:
        raise SetupError("incomplete_template", "Шаблон не содержит обязательные параметры Nikki.", {"missing": missing})
    return {
        "bytes": len(text.encode("utf-8")),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "rules": len(re.findall(r"(?m)^config rule\b", text)),
    }


def _policy_names(document: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    proxy_names = {
        str(item.get("name"))
        for item in document.get("proxies", []) or []
        if isinstance(item, Mapping) and item.get("name")
    }
    group_names = {
        str(item.get("name"))
        for item in document.get("proxy-groups", []) or []
        if isinstance(item, Mapping) and item.get("name")
    }
    return proxy_names, group_names


def validate_subscription_document(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_SUBSCRIPTION_BYTES:
        raise SetupError("invalid_subscription", "Подписка пустая или слишком большая.")
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SetupError("invalid_subscription", "Сервер вернул не Mihomo YAML.") from exc
    if not isinstance(document, Mapping):
        raise SetupError("invalid_subscription", "Сервер вернул не Mihomo YAML.")

    proxies = document.get("proxies", []) or []
    providers = document.get("proxy-providers", {}) or {}
    if not proxies and not providers:
        raise SetupError("invalid_subscription", "В подписке нет proxies или proxy-providers.")

    tun = document.get("tun", {}) or {}
    if isinstance(tun, Mapping) and bool(tun.get("enable", False)):
        raise SetupError("tun_profile", "Полученный профиль включает TUN, а этот мастер рассчитан на Redirect/TPROXY.")

    proxy_names, group_names = _policy_names(document)
    available_targets = proxy_names | group_names | {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
    missing_targets = sorted(REQUIRED_POLICY_TARGETS - available_targets)
    if missing_targets:
        raise SetupError(
            "profile_contract_mismatch",
            "Профиль не содержит цели, на которые ссылаются правила KatoVPN.",
            {"missing_targets": missing_targets},
        )

    dns = document.get("dns", {}) or {}
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "proxies_count": len(proxies) if isinstance(proxies, list) else 0,
        "proxy_providers_count": len(providers) if isinstance(providers, Mapping) else 0,
        "proxy_groups_count": len(group_names),
        "rules_count": len(document.get("rules", []) or []),
        "tun_enabled": bool(tun.get("enable", False)) if isinstance(tun, Mapping) else False,
        "dns_enabled": bool(dns.get("enable", False)) if isinstance(dns, Mapping) else False,
        "required_targets_ok": True,
    }


def fetch_and_validate_subscription(url: str, get: Callable[..., Any] = requests.get) -> dict[str, Any]:
    try:
        response = get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/yaml, application/yaml, */*"},
            timeout=(7, 25),
            allow_redirects=True,
        )
        status_code = int(response.status_code)
        if status_code != 200:
            raise SetupError("subscription_http", f"Сервер подписки ответил HTTP {status_code}.")
        final_scheme = urllib.parse.urlsplit(str(getattr(response, "url", url))).scheme.lower()
        if final_scheme != "https":
            raise SetupError(
                "subscription_insecure_redirect",
                "Ссылка подписки перенаправила запрос на небезопасный HTTP-адрес.",
            )
        raw = bytes(response.content)
    except SetupError:
        raise
    except Exception as exc:
        # Never include the exception text: requests may embed the tokenized URL.
        raise SetupError("subscription_unreachable", "Не удалось безопасно загрузить ссылку подписки.") from exc
    result = validate_subscription_document(raw)
    result["content_type"] = str(response.headers.get("content-type", "")).split(";", 1)[0]
    result["user_agent"] = USER_AGENT
    return result


class RemoteSession:
    def __init__(self, spec: ConnectionSpec):
        self.spec = spec
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.fingerprint = ""

    def connect(self) -> None:
        try:
            self.client.connect(
                hostname=self.spec.host,
                port=self.spec.port,
                username=self.spec.username,
                password=self.spec.password,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = self.client.get_transport()
            if transport is None:
                raise SetupError("ssh_transport", "SSH-соединение не установлено.")
            key = transport.get_remote_server_key()
            digest = hashlib.sha256(key.asbytes()).digest()
            self.fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
        except SetupError:
            raise
        except (paramiko.AuthenticationException, paramiko.BadAuthenticationType) as exc:
            raise SetupError("ssh_auth", "Роутер отклонил логин или пароль.") from exc
        except (paramiko.SSHException, socket.timeout, OSError) as exc:
            raise SetupError("ssh_connect", "Не удалось подключиться к SSH роутера.") from exc

    def close(self) -> None:
        self.client.close()

    def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str:
        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            stdout.channel.settimeout(timeout)
            data = stdout.read().decode("utf-8", "replace")
            error = stderr.read().decode("utf-8", "replace")
            exit_code = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, socket.timeout, OSError) as exc:
            raise SetupError("ssh_command", f"SSH-команда «{label}» не завершилась.") from exc
        if check and exit_code != 0:
            raise SetupError(
                "remote_command_failed",
                f"Роутер не выполнил этап «{label}».",
                {"exit_code": exit_code, "stderr_present": bool(error.strip())},
            )
        return data.strip()

    def write_file(self, remote_path: str, data: bytes, mode: str = "600") -> None:
        if not re.fullmatch(r"/tmp/[A-Za-z0-9._-]+", remote_path):
            raise SetupError("unsafe_remote_path", "Внутренний путь временного файла отклонён.")
        transport = self.client.get_transport()
        if transport is None:
            raise SetupError("ssh_transport", "SSH-соединение потеряно.")
        channel = transport.open_session(timeout=10)
        channel.settimeout(20)
        command = f"umask 077; cat > {shlex.quote(remote_path)} && chmod {mode} {shlex.quote(remote_path)}"
        channel.exec_command(command)
        try:
            channel.sendall(data)
            channel.shutdown_write()
            while channel.recv_ready():
                channel.recv(32768)
            exit_code = channel.recv_exit_status()
        except (socket.timeout, OSError, paramiko.SSHException) as exc:
            raise SetupError("ssh_upload", "Не удалось передать временный файл на роутер.") from exc
        finally:
            channel.close()
        if exit_code != 0:
            raise SetupError("ssh_upload", "Роутер не сохранил временный файл.")

    def read_file(self, remote_path: str, *, max_bytes: int = MAX_SUBSCRIPTION_BYTES) -> bytes:
        if not re.fullmatch(r"/etc/nikki/[A-Za-z0-9_./-]+", remote_path):
            raise SetupError("unsafe_remote_path", "Внутренний путь файла отклонён.")
        try:
            _stdin, stdout, stderr = self.client.exec_command(f"cat {shlex.quote(remote_path)}", timeout=20)
            raw = stdout.read(max_bytes + 1)
            error = stderr.read()
            exit_code = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, socket.timeout, OSError) as exc:
            raise SetupError("ssh_read", "Не удалось прочитать сформированный профиль Nikki.") from exc
        if exit_code != 0 or error.strip() or len(raw) > max_bytes:
            raise SetupError("ssh_read", "Сформированный профиль Nikki недоступен или слишком большой.")
        return raw


def _parse_version_pair(value: str) -> tuple[int, int]:
    match = re.match(r"\s*(\d+)\.(\d+)", value)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _package_version(status_text: str, package: str) -> str | None:
    blocks = re.split(r"\n\s*\n", status_text)
    for block in blocks:
        if re.search(rf"(?m)^Package:\s*{re.escape(package)}\s*$", block):
            match = re.search(r"(?m)^Version:\s*(\S+)", block)
            return match.group(1) if match else "unknown"
    return None


def _package_field(status_text: str, package: str, field: str) -> str | None:
    blocks = re.split(r"\n\s*\n", status_text)
    for block in blocks:
        if re.search(rf"(?m)^Package:\s*{re.escape(package)}\s*$", block):
            match = re.search(rf"(?m)^{re.escape(field)}:\s*(\S+)", block)
            return match.group(1) if match else None
    return None


def _package_arch_probe() -> str:
    return (
        "a=''; if [ -r /etc/openwrt_release ]; then . /etc/openwrt_release; a=${DISTRIB_ARCH:-}; fi; "
        "if [ -z \"$a\" ] && command -v opkg >/dev/null 2>&1; then "
        "a=$(opkg print-architecture 2>/dev/null | awk '$3>0 {a=$2} END {print a}'); fi; "
        "if [ -z \"$a\" ] && command -v apk >/dev/null 2>&1; then "
        "a=$(apk --print-arch 2>/dev/null | head -n 1); fi; "
        "[ -n \"$a\" ] && printf 'package_arch=%s\\n' \"$a\"; "
    )


def _installed_package_status_command(package_names: tuple[str, ...]) -> str:
    names = " ".join(shlex.quote(name) for name in package_names)
    return (
        "if command -v opkg >/dev/null 2>&1; then "
        f"for p in {names}; do opkg status \"$p\" 2>/dev/null || true; done; "
        "elif command -v apk >/dev/null 2>&1; then "
        "a='unknown'; if [ -r /etc/openwrt_release ]; then . /etc/openwrt_release; a=${DISTRIB_ARCH:-unknown}; fi; "
        f"for p in {names}; do "
        "v=$(apk list --installed --manifest \"$p\" 2>/dev/null | awk -v p=\"$p\" '$1==p {print $2; exit}'); "
        "[ -z \"$v\" ] || printf 'Package: %s\\nVersion: %s\\nArchitecture: %s\\n\\n' \"$p\" \"$v\" \"$a\"; done; fi"
    )


def _verify_installed_versions_command(manager: str, package_names: tuple[str, ...]) -> str:
    names = " ".join(shlex.quote(name) for name in package_names)
    if manager == "apk":
        version_command = (
            "apk list --installed --manifest \"$p\" 2>/dev/null | "
            "awk -v p=\"$p\" '$1==p {print $2; exit}'"
        )
    else:
        version_command = "opkg status \"$p\" 2>/dev/null | awk -F': ' '$1==\"Version\" {print $2; exit}'"
    return (
        f"set -eu; for p in {names}; do v=$({version_command}); "
        "[ -n \"$v\" ] || exit 1; printf '%s=%s\\n' \"$p\" \"$v\"; done"
    )


def _semver(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else None


def _semver_text(value: str | None) -> str | None:
    parsed = _semver(value)
    return ".".join(str(part) for part in parsed) if parsed else None


def fetch_latest_nikki_release(get: Callable[..., Any] = requests.get) -> dict[str, Any]:
    """Return sanitized official release metadata; diagnostics never expose raw HTTP errors."""
    try:
        response = get(
            NIKKI_RELEASE_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=(5, 12),
            allow_redirects=True,
        )
        if int(response.status_code) != 200:
            raise ValueError("unexpected status")
        final = urllib.parse.urlsplit(str(getattr(response, "url", NIKKI_RELEASE_API)))
        if final.scheme.lower() != "https" or final.hostname not in {"api.github.com", "github.com"}:
            raise ValueError("unexpected redirect")
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise ValueError("unexpected payload")
        tag = str(payload.get("tag_name", ""))
        if _semver(tag) is None:
            raise ValueError("unexpected tag")
        assets = []
        for item in payload.get("assets", []) or []:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name", ""))
            if re.fullmatch(r"[A-Za-z0-9._+-]{1,180}", name):
                assets.append(name)
        return {
            "status": "available",
            "tag": tag,
            "version": ".".join(str(part) for part in _semver(tag) or ()),
            "published_at": str(payload.get("published_at", ""))[:32],
            "url": NIKKI_RELEASE_PAGE,
            "assets": assets[:200],
        }
    except Exception:
        return {
            "status": "unavailable",
            "tag": None,
            "version": None,
            "published_at": None,
            "url": NIKKI_RELEASE_PAGE,
            "assets": [],
        }


def _nikki_feed_branch(firmware_version: str) -> str | None:
    if "24.10" in firmware_version:
        return "openwrt-24.10"
    if "25.12" in firmware_version:
        return "openwrt-25.12"
    if firmware_version.strip().upper() == "SNAPSHOT":
        return "SNAPSHOT"
    return None


def fetch_latest_nikki_packages(
    firmware_version: str,
    package_arch: str | None,
    get: Callable[..., Any] = requests.get,
) -> dict[str, Any]:
    """Read exact compatible package versions from Nikki's official feed index."""
    branch = _nikki_feed_branch(firmware_version)
    if not branch or not package_arch or not re.fullmatch(r"[A-Za-z0-9_+.-]{1,80}", package_arch):
        return {"status": "unsupported", "branch": branch, "url": None, "packages": {}}
    index_url = f"{NIKKI_FEED_BASE}/{branch}/{urllib.parse.quote(package_arch, safe='')}/nikki/index.json"
    try:
        response = get(
            index_url,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=(5, 12),
            allow_redirects=True,
        )
        if int(response.status_code) != 200:
            raise ValueError("unexpected status")
        final = urllib.parse.urlsplit(str(getattr(response, "url", index_url)))
        if final.scheme.lower() != "https" or final.hostname != "nikkinikki.pages.dev":
            raise ValueError("unexpected redirect")
        payload = response.json()
        raw_packages = payload.get("packages") if isinstance(payload, Mapping) else None
        if not isinstance(raw_packages, Mapping):
            raise ValueError("unexpected payload")
        packages: dict[str, str] = {}
        for name in ("nikki", "luci-app-nikki", "mihomo-meta", "mihomo-alpha"):
            value = str(raw_packages.get(name, ""))
            if re.fullmatch(r"[A-Za-z0-9._+~:-]{1,100}", value):
                packages[name] = value
        if not {"nikki", "luci-app-nikki"}.issubset(packages):
            raise ValueError("incomplete package index")
        return {"status": "available", "branch": branch, "url": index_url, "packages": packages}
    except Exception:
        return {"status": "unavailable", "branch": branch, "url": index_url, "packages": {}}


def _update_report(
    *,
    nikki_version: str | None,
    luci_version: str | None,
    mihomo_runtime: str,
    mihomo_package_name: str | None,
    mihomo_package_version: str | None,
    package_state: Mapping[str, str],
    official_release: Mapping[str, Any],
    official_packages: Mapping[str, Any],
    free_overlay_kb: int = 0,
) -> dict[str, Any]:
    manager = package_state.get("package_manager", "unknown")
    package_versions = official_packages.get("packages", {})
    if not isinstance(package_versions, Mapping):
        package_versions = {}

    nikki_candidate = package_state.get("luci_candidate") or package_state.get("nikki_candidate") or None
    nikki_latest_raw = str(package_versions.get("luci-app-nikki") or official_release.get("version") or "") or None
    nikki_installed_text = _semver_text(luci_version)
    nikki_latest_text = _semver_text(nikki_latest_raw)
    nikki_installed = _semver(nikki_installed_text)
    nikki_latest = _semver(nikki_latest_text)
    nikki_packages_ready = {"nikki", "luci-app-nikki"}.issubset(package_versions)

    if nikki_latest and nikki_installed and nikki_latest > nikki_installed:
        nikki_status = "compatible_update_available" if nikki_packages_ready else "manual_update_available"
    elif nikki_latest and nikki_installed and nikki_latest <= nikki_installed:
        nikki_status = "current"
    else:
        nikki_status = "unknown"

    core_installed_text = _semver_text(mihomo_runtime) or _semver_text(mihomo_package_version)
    core_package = mihomo_package_name if mihomo_package_name in {"mihomo-meta", "mihomo-alpha"} else "mihomo-meta"
    core_latest_raw = str(package_versions.get(core_package, "")) or None
    core_latest_text = _semver_text(core_latest_raw)
    core_candidate_key = "mihomo_alpha_candidate" if core_package == "mihomo-alpha" else "mihomo_meta_candidate"
    core_candidate = package_state.get(core_candidate_key) or None
    core_installed = _semver(core_installed_text)
    core_latest = _semver(core_latest_text)
    core_package_ready = bool(core_latest_text and package_versions.get(core_package))
    if core_latest and core_installed and core_latest > core_installed:
        core_status = "compatible_update_available" if core_package_ready else "manual_update_available"
    elif core_latest and core_installed and core_latest <= core_installed:
        core_status = "current"
    else:
        core_status = "unknown"

    update_statuses = {"package_update_available", "compatible_update_available"}
    supported_manager = manager in {"opkg", "apk"}
    nikki_can_update = nikki_status in update_statuses and nikki_packages_ready and supported_manager
    core_can_update = core_status in update_statuses and core_package_ready and supported_manager
    adopts_official_package = bool(
        core_can_update and mihomo_package_name not in {"mihomo-meta", "mihomo-alpha"}
    )
    core_storage = {
        "available_kb": free_overlay_kb,
        "required_kb": MIHOMO_ADOPTION_MIN_FREE_KB if adopts_official_package else 0,
        "checked_again_before_install": True,
    }
    if (
        adopts_official_package
        and free_overlay_kb
        and free_overlay_kb < MIHOMO_ADOPTION_MIN_FREE_KB
    ):
        core_status = "insufficient_space"
        core_can_update = False

    return {
        "package_manager": manager,
        "feed_configured": package_state.get("nikki_feed") == "1",
        "official_feed": official_packages.get("url"),
        "nikki": {
            "installed": nikki_installed_text or luci_version,
            "service_installed": nikki_version,
            "luci_installed": luci_version,
            "latest": nikki_latest_text,
            "package_candidate": nikki_candidate,
            "status": nikki_status,
            "can_update": nikki_can_update,
            "update_method": "official_nikki_feed" if nikki_can_update else None,
            "target_packages": {
                name: str(package_versions[name])
                for name in ("nikki", "luci-app-nikki")
                if name in package_versions
            },
            "official_url": official_release.get("url") or NIKKI_RELEASE_PAGE,
        },
        "mihomo": {
            "installed": core_installed_text or "не определена",
            "runtime": mihomo_runtime or None,
            "package": mihomo_package_name,
            "package_installed": mihomo_package_version,
            "latest": core_latest_text,
            "package_candidate": core_candidate,
            "status": core_status,
            "can_update": core_can_update,
            "update_method": "official_nikki_feed" if core_can_update else None,
            "target_package": core_package,
            "target_package_version": str(package_versions.get(core_package, "")) or None,
            "adopts_official_package": adopts_official_package,
            "storage": core_storage,
            "official_url": official_packages.get("url"),
        },
    }


def validate_backup_id(value: str) -> str:
    value = value.strip()
    if not BACKUP_ID_PATTERN.fullmatch(value):
        raise SetupError("invalid_backup_id", "Выбран некорректный backup Nikki.")
    return value


def _parse_backups(value: str) -> list[dict[str, Any]]:
    backups: list[dict[str, Any]] = []
    for line in value.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not BACKUP_ID_PATTERN.fullmatch(parts[0]):
            continue
        created_epoch = int(parts[1]) if parts[1].isdigit() else 0
        size_kb = int(parts[2]) if parts[2].isdigit() else 0
        enabled = parts[3] if parts[3] in {"0", "1"} else "unknown"
        backups.append(
            {
                "id": parts[0],
                "created_at": datetime.fromtimestamp(created_epoch, timezone.utc).isoformat() if created_epoch else None,
                "size_kb": size_kb,
                "enabled": enabled,
            }
        )
    return backups[:20]


def _new_backup_id(fingerprint: str) -> str:
    return (
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        + "-"
        + hashlib.sha256(fingerprint.encode()).hexdigest()[:8]
        + "-"
        + secrets.token_hex(2)
    )


def preflight_router(
    spec: ConnectionSpec,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    subscription_fetcher: Callable[[str], dict[str, Any]] = fetch_and_validate_subscription,
    release_fetcher: Callable[[], dict[str, Any]] = fetch_latest_nikki_release,
    package_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_latest_nikki_packages,
    check_subscription: bool = True,
) -> dict[str, Any]:
    progress("connect", "running", "Подключаемся к роутеру по SSH")
    session = session_factory(spec)
    try:
        session.connect()
        progress("connect", "done", "SSH-соединение установлено")
        progress("inspect", "running", "Проверяем прошивку, Nikki и firewall")

        board_raw = session.run("ubus call system board", label="сведения о роутере")
        try:
            board = json.loads(board_raw)
        except json.JSONDecodeError as exc:
            raise SetupError("invalid_board_info", "Роутер вернул неожиданные сведения о системе.") from exc

        checks_raw = session.run(
            "for c in uci fw4 nft opkg apk; do command -v \"$c\" >/dev/null 2>&1 && echo \"$c=1\" || echo \"$c=0\"; done; "
            "[ -x /etc/init.d/nikki ] && echo nikki_init=1 || echo nikki_init=0; "
            "command -v iptables >/dev/null 2>&1 && echo iptables=1 || echo iptables=0",
            label="компоненты роутера",
        )
        checks = dict(line.split("=", 1) for line in checks_raw.splitlines() if "=" in line)
        packages = session.run(
            _installed_package_status_command(("nikki", "luci-app-nikki", "mihomo-meta", "mihomo-alpha", "mihomo")),
            label="версии Nikki и Mihomo",
            check=False,
        )
        package_updates_raw = session.run(
            _package_arch_probe()
            + "if command -v opkg >/dev/null 2>&1; then "
            "echo package_manager=opkg; "
            "grep -RqsE '(OpenWrt-nikki|[[:space:]]nikki[[:space:]])' /etc/opkg 2>/dev/null && echo nikki_feed=1 || echo nikki_feed=0; "
            "opkg list-upgradable 2>/dev/null | awk '$1==\"nikki\" {print \"nikki_candidate=\"$5} "
            "$1==\"luci-app-nikki\" {print \"luci_candidate=\"$5} "
            "$1==\"mihomo-meta\" {print \"mihomo_meta_candidate=\"$5} "
            "$1==\"mihomo-alpha\" {print \"mihomo_alpha_candidate=\"$5}'; "
            "elif command -v apk >/dev/null 2>&1; then echo package_manager=apk; "
            "grep -RqsE '(OpenWrt-nikki|[[:space:]]nikki[[:space:]])' /etc/apk 2>/dev/null && echo nikki_feed=1 || echo nikki_feed=0; "
            "else echo package_manager=unknown; echo nikki_feed=0; fi",
            label="доступные обновления",
            check=False,
        )
        package_state = dict(line.split("=", 1) for line in package_updates_raw.splitlines() if "=" in line)
        free_raw = session.run("df -k /overlay 2>/dev/null | awk 'NR==2 {print $4}'", label="свободное место", check=False)
        dns_redirect = session.run("uci -q get dhcp.@dnsmasq[0].dns_redirect || true", label="DNS redirect", check=False)
        nikki_status = session.run("/etc/init.d/nikki status 2>/dev/null || true", label="статус Nikki", check=False)
        mihomo_runtime = session.run(
            "if command -v mihomo >/dev/null 2>&1; then mihomo -v 2>/dev/null | head -n 1; "
            "elif [ -x /usr/libexec/mihomo ]; then /usr/libexec/mihomo -v 2>/dev/null | head -n 1; "
            "else echo unknown; fi",
            label="версия Mihomo Core",
            check=False,
        )
        current_modes_raw = session.run(
            "printf 'tcp=%s\\nudp=%s\\n' \"$(uci -q get nikki.proxy.tcp_mode || echo unknown)\" "
            "\"$(uci -q get nikki.proxy.udp_mode || echo unknown)\"",
            label="текущий режим Nikki",
            check=False,
        )
        current_modes = dict(line.split("=", 1) for line in current_modes_raw.splitlines() if "=" in line)
        backups_raw = session.run(
            "for d in /root/katovpn-nikki-backups/*; do [ -d \"$d\" ] || continue; "
            "id=${d##*/}; case \"$id\" in "
            "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]|"
            "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) continue ;; esac; "
            "[ -f \"$d/nikki.uci\" ] || continue; "
            "ts=$(stat -c %Y \"$d\" 2>/dev/null || echo 0); size=$(du -sk \"$d\" 2>/dev/null | awk '{print $1}'); "
            "enabled=$(cat \"$d/original-enabled\" 2>/dev/null || echo unknown); "
            "printf '%s\\t%s\\t%s\\t%s\\n' \"$id\" \"$ts\" \"${size:-0}\" \"$enabled\"; done | sort -r | head -20",
            label="backups Nikki",
            check=False,
        )

        release = board.get("release", {}) if isinstance(board, Mapping) else {}
        firmware_version = str(release.get("version", ""))
        nikki_version = _package_version(packages, "nikki")
        luci_version = _package_version(packages, "luci-app-nikki")
        mihomo_meta_version = _package_version(packages, "mihomo-meta")
        mihomo_alpha_version = _package_version(packages, "mihomo-alpha")
        mihomo_legacy_version = _package_version(packages, "mihomo")
        mihomo_package_name = "mihomo-meta" if mihomo_meta_version else "mihomo-alpha" if mihomo_alpha_version else None
        mihomo_package_version = mihomo_meta_version or mihomo_alpha_version or mihomo_legacy_version
        package_arch = package_state.get("package_arch") or (
            _package_field(packages, mihomo_package_name, "Architecture") if mihomo_package_name else None
        ) or _package_field(packages, "mihomo", "Architecture") or _package_field(packages, "nikki", "Architecture")
        free_kb = int(free_raw) if free_raw.isdigit() else 0

        blockers: list[str] = []
        if _parse_version_pair(firmware_version) < (24, 10):
            blockers.append("Нужен OpenWrt/ImmortalWrt 24.10 или новее.")
        if any(checks.get(name) != "1" for name in ("uci", "fw4", "nft", "nikki_init")):
            blockers.append("Не найдены UCI, firewall4/nftables или установленный Nikki.")
        if not nikki_version or not luci_version:
            blockers.append("Nikki и luci-app-nikki должны быть установлены до запуска режима V1.")
        if free_kb and free_kb < MIN_FREE_OVERLAY_KB:
            blockers.append("На overlay недостаточно свободного места для backup и профиля.")

        warnings: list[str] = []
        if dns_redirect.strip() == "1":
            warnings.append(
                "На роутере одновременно включён перехват DNS средствами dnsmasq и Nikki. "
                "Сейчас это не является ошибкой: мастер оставит настройку без изменений. "
                "Если после применения перестанут открываться сайты, попробуйте отключить DNS Redirect в dnsmasq."
            )
        if checks.get("iptables") == "1":
            warnings.append("iptables найден, но этот профиль использует firewall4/nftables.")

        progress("inspect", "done" if not blockers else "error", "Совместимость проверена")
        if check_subscription:
            progress("subscription", "running", "Проверяем профиль подписки и User-Agent")
            subscription = subscription_fetcher(spec.subscription_url)
            progress("subscription", "done", "Получен совместимый Mihomo-профиль")
        else:
            subscription = {"skipped": True}
            progress("subscription", "done", "Подписка не нужна для режима обновления")
        progress("updates", "running", "Проверяем версии Nikki и Mihomo Core")
        official_release = release_fetcher()
        official_packages = package_fetcher(firmware_version, package_arch)
        updates = _update_report(
            nikki_version=nikki_version,
            luci_version=luci_version,
            mihomo_runtime=mihomo_runtime,
            mihomo_package_name=mihomo_package_name,
            mihomo_package_version=mihomo_package_version,
            package_state=package_state,
            official_release=official_release,
            official_packages=official_packages,
            free_overlay_kb=free_kb,
        )
        if updates["mihomo"].get("status") == "insufficient_space":
            storage = updates["mihomo"]["storage"]
            warnings.append(
                "Официальный Mihomo Core не будет устанавливаться: для первой установки пакета "
                f"нужно минимум {storage['required_kb'] // 1024} МБ свободного места на overlay, "
                f"доступно {storage['available_kb'] // 1024} МБ. Настройку профиля можно продолжить без обновления ядра."
            )
        elif updates["mihomo"].get("adopts_official_package"):
            warnings.append(
                "Mihomo Core запущен, но пакет mihomo-meta/mihomo-alpha не зарегистрирован. "
                "При выбранном обновлении мастер установит официальный пакет mihomo-meta из репозитория Nikki."
            )
        progress("updates", "done", "Проверка версий завершена")

        return {
            "compatible": not blockers,
            "blockers": blockers,
            "warnings": warnings,
            "fingerprint": session.fingerprint,
            "router": {
                "model": str(board.get("model", "неизвестно")),
                "hostname": str(board.get("hostname", "неизвестно")),
                "firmware": str(release.get("description", firmware_version or "неизвестно")),
                "firmware_version": firmware_version,
                "board_name": str(board.get("board_name", "неизвестно")),
                "free_overlay_kb": free_kb,
            },
            "nikki": {
                "version": nikki_version,
                "luci_version": luci_version,
                "mihomo_core_version": updates["mihomo"]["installed"],
                "mihomo_package": mihomo_package_name,
                "mihomo_package_version": mihomo_package_version,
                "package_arch": package_arch,
                "status": nikki_status or "unknown",
                "firewall_backend": "firewall4/nftables" if checks.get("fw4") == checks.get("nft") == "1" else "unknown",
                "current_mode": f"TCP {current_modes.get('tcp', 'unknown')} + UDP {current_modes.get('udp', 'unknown')}",
                "current_tun": "tun" in {current_modes.get("tcp"), current_modes.get("udp")},
                "mode": "TCP Redirect + UDP TPROXY",
                "tun": False,
            },
            "subscription": subscription,
            "updates": updates,
            "backups": _parse_backups(backups_raw),
            "profile_name": PROFILE_NAME,
            "user_agent": USER_AGENT,
        }
    finally:
        session.close()


def _backup_command(backup_dir: str, original_enabled: str) -> str:
    quoted = shlex.quote(backup_dir)
    return (
        f"set -eu; mkdir -p {quoted}; chmod 700 {quoted}; "
        f"cp -p /etc/config/nikki {quoted}/nikki.uci; "
        f"printf '%s\\n' {shlex.quote(original_enabled)} > {quoted}/original-enabled; "
        f"[ ! -f /etc/nikki/mixin.yaml ] || cp -p /etc/nikki/mixin.yaml {quoted}/mixin.yaml; "
        f"[ ! -d /etc/nikki/profiles ] || cp -a /etc/nikki/profiles {quoted}/profiles; "
        f"[ ! -d /etc/nikki/subscriptions ] || cp -a /etc/nikki/subscriptions {quoted}/subscriptions"
    )


def _connect_pinned(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    session_factory: Callable[[ConnectionSpec], RemoteSession],
) -> RemoteSession:
    session = session_factory(spec)
    session.connect()
    if not secrets.compare_digest(session.fingerprint, str(expected_fingerprint)):
        session.close()
        raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился. Войдите заново и проверьте адрес.")
    return session


def _simple_key_values(value: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in value.splitlines() if "=" in line)


def create_nikki_backup(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> dict[str, Any]:
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    backup_id = _new_backup_id(session.fingerprint)
    backup_dir = f"{BACKUP_ROOT}/{backup_id}"
    try:
        progress("backup", "running", "Создаём резервную копию настроек VPN")
        original_enabled = session.run("uci -q get nikki.config.enabled || echo 0", label="исходное состояние", check=False) or "0"
        session.run(_backup_command(backup_dir, original_enabled), label="backup Nikki", timeout=45)
        verified = session.run(
            f"[ -s {shlex.quote(backup_dir + '/nikki.uci')} ] && [ -s {shlex.quote(backup_dir + '/original-enabled')} ] && echo 1 || echo 0",
            label="проверка созданного backup",
            check=False,
        )
        if verified.strip() != "1":
            raise SetupError("backup_verification", "Роутер не подтвердил целостность созданной резервной копии.")
        progress("backup", "done", "Резервная копия создана")
        return {"operation": "backup", "backup_id": backup_id, "backup_path": backup_dir}
    finally:
        session.close()


def delete_nikki_backup(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    backup_id: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> dict[str, Any]:
    backup_id = validate_backup_id(backup_id)
    backup_dir = f"{BACKUP_ROOT}/{backup_id}"
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    try:
        exists = session.run(
            f"[ -d {shlex.quote(backup_dir)} ] && [ -s {shlex.quote(backup_dir + '/nikki.uci')} ] && echo 1 || echo 0",
            label="проверка удаляемого backup",
            check=False,
        )
        if exists.strip() != "1":
            raise SetupError("backup_not_found", "Выбранная резервная копия не найдена или повреждена.")
        progress("backup_delete", "running", "Удаляем выбранную резервную копию")
        # The identifier is strictly validated and the target is anchored below BACKUP_ROOT.
        session.run(f"rm -rf -- {shlex.quote(backup_dir)}", label="удаление backup", timeout=30)
        deleted = session.run(
            f"[ ! -e {shlex.quote(backup_dir)} ] && echo deleted || echo present",
            label="проверка удаления backup",
            check=False,
        )
        if deleted.strip() != "deleted":
            raise SetupError("backup_delete_failed", "Роутер не подтвердил удаление резервной копии.")
        progress("backup_delete", "done", "Резервная копия удалена")
        return {"operation": "backup_delete", "backup_id": backup_id}
    finally:
        session.close()


def install_adblock(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> dict[str, Any]:
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    package_text = " ".join(ADBLOCK_PACKAGES)
    try:
        progress("adblock", "running", "Проверяем ресурсы и официальные пакеты AdBlock")
        state = _simple_key_values(
            session.run(
                "mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo); printf 'memory_kb=%s\\n' \"${mem:-0}\"; "
                "if command -v opkg >/dev/null 2>&1; then echo opkg=1; echo apk=0; "
                "elif command -v apk >/dev/null 2>&1; then echo opkg=0; echo apk=1; "
                "else echo opkg=0; echo apk=0; fi",
                label="проверка AdBlock",
                check=False,
            )
        )
        try:
            memory_kb = int(state.get("memory_kb", "0"))
        except ValueError:
            memory_kb = 0
        if memory_kb < ADBLOCK_MIN_RAM_KB:
            raise SetupError(
                "adblock_memory",
                "AdBlock доступен только для роутеров класса 512 МБ оперативной памяти.",
                {"required_mb": ADBLOCK_MIN_RAM_KB // 1024, "detected_mb": memory_kb // 1024},
            )
        if state.get("opkg") == "1":
            session.run("opkg update", label="обновление списка пакетов AdBlock", timeout=120)
            availability = session.run(
                "for p in adblock luci-app-adblock luci-i18n-adblock-ru; do "
                "opkg list \"$p\" 2>/dev/null | awk -v p=\"$p\" '$1==p {found=1} END {print p \"=\" (found?1:0)}'; done",
                label="проверка доступности пакетов AdBlock",
                check=False,
            )
            dry_run_command = f"opkg install --noaction {package_text}; rc=$?; echo __KATO_ADBLOCK_DRYRUN__=$rc; exit $rc"
            install_command = f"opkg install {package_text}"
        elif state.get("apk") == "1":
            session.run("apk update", label="обновление списка пакетов AdBlock", timeout=120)
            availability = session.run(
                "for p in adblock luci-app-adblock luci-i18n-adblock-ru; do "
                "apk search -x \"$p\" 2>/dev/null | grep -q . && echo \"$p=1\" || echo \"$p=0\"; done",
                label="проверка доступности пакетов AdBlock",
                check=False,
            )
            dry_run_command = f"apk add --simulate {package_text}; rc=$?; echo __KATO_ADBLOCK_DRYRUN__=$rc; exit $rc"
            install_command = f"apk add {package_text}"
        else:
            raise SetupError("package_manager_missing", "Не найден поддерживаемый пакетный менеджер OpenWrt.")
        available = _simple_key_values(availability)
        if any(available.get(package) != "1" for package in ADBLOCK_PACKAGES):
            raise SetupError("adblock_packages_unavailable", "Официальные пакеты AdBlock недоступны для этой прошивки.")
        dry_run = session.run(dry_run_command, label="проверка установки AdBlock", timeout=120)
        if "__KATO_ADBLOCK_DRYRUN__=0" not in dry_run:
            raise SetupError("adblock_dry_run", "Пакетный менеджер не подтвердил безопасную установку AdBlock.")
        progress("adblock", "running", "Устанавливаем AdBlock и русскую панель управления")
        session.run(install_command, label="установка AdBlock", timeout=180)
        verified = _simple_key_values(
            session.run(
                "for p in adblock luci-app-adblock luci-i18n-adblock-ru; do "
                "if opkg status \"$p\" 2>/dev/null | grep -q '^Status: .* installed' || apk info -e \"$p\" >/dev/null 2>&1; "
                "then echo \"$p=1\"; else echo \"$p=0\"; fi; done",
                label="проверка AdBlock после установки",
                check=False,
            )
        )
        if any(verified.get(package) != "1" for package in ADBLOCK_PACKAGES):
            raise SetupError("adblock_verification", "После установки не найдены все компоненты AdBlock.")
        progress("adblock", "done", "AdBlock установлен")
        return {"operation": "adblock_install", "packages": list(ADBLOCK_PACKAGES)}
    finally:
        session.close()


def collect_router_logs(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    kind: str,
    *,
    source: str = "all",
    lines: int = 500,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> dict[str, Any]:
    if kind not in {"connections", "debug"}:
        raise SetupError("invalid_log_kind", "Неизвестный тип журнала.")
    source = str(source)
    if source not in {"all", "core", "app", "system"}:
        raise SetupError("invalid_log_source", "Неизвестный источник журнала VPN.")
    try:
        lines = int(lines)
    except (TypeError, ValueError) as exc:
        raise SetupError("invalid_log_lines", "Некорректное число строк журнала.") from exc
    if not 50 <= lines <= 2000:
        raise SetupError("invalid_log_lines", "Можно выгрузить от 50 до 2000 последних строк.")
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    try:
        if kind == "connections":
            sources = {
                "app": ("App Log", "echo '# App Log — Nikki'; tail -n " + str(lines) + " /var/log/nikki/app.log 2>/dev/null"),
                "core": ("Core Log", "echo '# Core Log — Mihomo'; tail -n " + str(lines) + " /var/log/nikki/core.log 2>/dev/null"),
                "system": ("OpenWrt", "echo '# OpenWrt logread — Nikki'; logread -e nikki 2>/dev/null | tail -n " + str(lines)),
            }
            selected = ["app", "core", "system"] if source == "all" else [source]
            command = "; echo; ".join(sources[item][1] for item in selected)
            label = "журнал VPN: Все источники" if source == "all" else f"журнал VPN: {sources[source][0]}"
        else:
            # Upstream debug.sh restarts Nikki when disabled. Use it only while already enabled;
            # otherwise collect a read-only subset that never changes service state.
            command = (
                "enabled=$(uci -q get nikki.config.enabled || echo 0); "
                "if [ \"$enabled\" = 1 ] && [ -x /etc/nikki/scripts/debug.sh ]; then /etc/nikki/scripts/debug.sh; else "
                "echo '# KatoVPN read-only Nikki diagnostic'; ubus call system board 2>/dev/null; uname -a; "
                "echo '## packages'; (opkg status nikki luci-app-nikki mihomo-meta 2>/dev/null || apk info -a nikki luci-app-nikki mihomo-meta 2>/dev/null); "
                "echo '## service'; /etc/init.d/nikki info 2>/dev/null || /etc/init.d/nikki status 2>/dev/null; "
                "echo '## config'; uci show nikki 2>/dev/null; echo '## ip rule'; ip rule list; "
                "echo '## nftables'; nft list table inet nikki 2>/dev/null; fi"
            )
            label = "диагностический отчёт Nikki"
        raw = session.run(command, label=label, timeout=90, check=False)
        clean = sanitize_diagnostic_text(raw, extra_secrets=[spec.password, spec.subscription_url])
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        suffix = f"vpn-{source}" if kind == "connections" else "debug"
        return {
            "operation": "log_export",
            "kind": kind,
            "source": source if kind == "connections" else "debug",
            "filename": f"katovpn-{suffix}-{timestamp}.txt",
            "text": clean,
        }
    finally:
        session.close()


def _wait_for_verified_router(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    command: str,
    label: str,
    verifier: Callable[[str], bool],
    *,
    timeout_seconds: float,
    session_factory: Callable[[ConnectionSpec], RemoteSession],
    sleep: Callable[[float], None] = time.sleep,
) -> RemoteSession | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        candidate = session_factory(spec)
        try:
            candidate.connect()
            if not secrets.compare_digest(candidate.fingerprint, expected_fingerprint):
                candidate.close()
                raise SetupError("router_fingerprint_changed", "SSH-ключ роутера изменился во время переподключения.")
            value = candidate.run(command, label=label, timeout=15, check=False)
            if verifier(value):
                return candidate
        except SetupError as exc:
            candidate.close()
            if exc.code == "router_fingerprint_changed":
                raise
        else:
            candidate.close()
        sleep(3)
    return None


def _confirm_router_rollback(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    path: str,
    original_sha256: str,
    *,
    session_factory: Callable[[ConnectionSpec], RemoteSession],
) -> bool:
    try:
        session = _connect_pinned(spec, expected_fingerprint, session_factory)
        try:
            current = session.run(f"sha256sum {shlex.quote(path)} 2>/dev/null | awk '{{print $1}}'", label="проверка автоматического отката", check=False)
            return bool(original_sha256 and secrets.compare_digest(current.strip(), original_sha256.strip()))
        finally:
            session.close()
    except SetupError:
        return False


def change_wifi_configuration(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    radio: str,
    password: str,
    country: str,
    section: str | None = None,
    ssid: str | None = None,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    radio = _validate_uci_section(radio, label="радиомодуля")
    country = str(country).upper()
    if country not in {"RU", "CN"}:
        raise SetupError("invalid_wifi_country", "Код страны Wi‑Fi должен быть RU или CN.")
    creating = section is None
    password_changed = bool(password)
    if creating or password_changed:
        password = validate_wifi_password(password)
    ssid = validate_wifi_ssid(ssid or "")
    if not creating:
        section = _validate_uci_section(section or "", label="Wi‑Fi сети")

    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    operation_id = _new_backup_id(session.fingerprint)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    try:
        capability = _simple_key_values(
            session.run(
                f"printf 'radio_type=%s\\n' \"$(uci -q get wireless.{radio}.type)\"; "
                + (
                    "printf 'mode=%s\\ndevice=%s\\n' "
                    f"\"$(uci -q get wireless.{section}.mode)\" \"$(uci -q get wireless.{section}.device)\"; "
                    if section else ""
                )
                + "command -v start-stop-daemon >/dev/null 2>&1 && echo rollback=1 || echo rollback=0; "
                "command -v sha256sum >/dev/null 2>&1 && echo sha256=1 || echo sha256=0; "
                "if uci show wireless 2>/dev/null | grep -Eq \"\\.encryption='?(sae|sae-mixed)\" || "
                "((opkg list-installed 2>/dev/null; apk info 2>/dev/null) | "
                "grep -Eq '^(wpad|hostapd)([[:space:]]|-(basic-)?(mbedtls|openssl|wolfssl)([[:space:]]|$))'); "
                "then echo sae=1; else echo sae=0; fi; "
                "sha256sum /etc/config/wireless 2>/dev/null | awk '{print \"config_sha256=\" $1}'",
                label="проверка безопасной настройки Wi-Fi",
                check=False,
            )
        )
        if capability.get("rollback") != "1" or capability.get("sha256") != "1" or not capability.get("radio_type"):
            raise SetupError("wifi_rollback_unavailable", "Роутер не поддерживает безопасный таймер отката Wi‑Fi.")
        if capability.get("sae") != "1":
            raise SetupError("wifi_sae_unavailable", "Установленный Wi‑Fi модуль не подтвердил поддержку WPA2/WPA3 Mixed Mode.")
        if section and capability.get("mode") != "ap":
            raise SetupError("wifi_target_changed", "Выбранная Wi‑Fi сеть больше не работает в режиме точки доступа.")

        if password_changed:
            session.write_file("/tmp/kato-wifi-key", password.encode("utf-8"))
        session.write_file("/tmp/kato-wifi-ssid", ssid.encode("utf-8"))
        progress("rollback", "running", "Включаем автоматический откат через две минуты")
        session.run(build_wifi_rollback_command(operation_id), label="таймер отката Wi-Fi", timeout=20)
        progress("wifi", "running", "Применяем новые параметры Wi‑Fi. При необходимости подключитесь к сети заново")
        if creating:
            target_section = "kato_wifi_" + re.sub(r"[^0-9a-f]", "", operation_id)[-8:]
            try:
                session.run(
                    build_wifi_create_command(radio, country, operation_id),
                    label="создание Wi-Fi сети",
                    timeout=30,
                )
            except SetupError as exc:
                if exc.code != "ssh_command":
                    raise
        else:
            target_section = str(section)
            try:
                session.run(
                    build_wifi_apply_command(
                        target_section,
                        radio,
                        country,
                        operation_id,
                        password_changed=password_changed,
                    ),
                    label="изменение Wi-Fi",
                    timeout=30,
                )
            except SetupError as exc:
                if exc.code != "ssh_command":
                    raise
    finally:
        session.close()

    ssid_sha256 = hashlib.sha256(ssid.encode("utf-8")).hexdigest()
    password_sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest() if password_changed else None
    verify_command = (
        f"printf 'mode=%s\\ndevice=%s\\ncountry=%s\\n' \"$(uci -q get wireless.{target_section}.mode)\" "
        f"\"$(uci -q get wireless.{target_section}.device)\" \"$(uci -q get wireless.{radio}.country)\"; "
        f"[ \"$(uci -q get wireless.{radio}.disabled)\" = 1 ] && echo radio_enabled=0 || echo radio_enabled=1; "
        f"ssid=$(uci -q get wireless.{target_section}.ssid); printf '%s' \"$ssid\" | sha256sum | "
        "awk '{print \"ssid_sha256=\" $1}'; "
        + (
            f"printf 'encryption=%s\\n' \"$(uci -q get wireless.{target_section}.encryption)\"; "
            f"key=$(uci -q get wireless.{target_section}.key); printf '%s' \"$key\" | sha256sum | "
            "awk '{print \"key_sha256=\" $1}'"
            if password_changed
            else ""
        )
    )

    def verified(value: str) -> bool:
        state = _simple_key_values(value)
        matches = (
            state.get("mode") == "ap"
            and state.get("device") == radio
            and state.get("country") == country
            and state.get("radio_enabled") == "1"
            and state.get("ssid_sha256") == ssid_sha256
        )
        if password_changed:
            matches = matches and state.get("encryption") == "sae-mixed" and state.get("key_sha256") == password_sha256
        return matches

    progress("reconnect", "running", "Ожидаем переподключение и подтверждаем Wi‑Fi")
    confirmed_session = _wait_for_verified_router(
        spec,
        expected_fingerprint,
        verify_command,
        "проверка Wi-Fi после изменения",
        verified,
        timeout_seconds=NETWORK_ROLLBACK_SECONDS + 12,
        session_factory=session_factory,
        sleep=sleep,
    )
    if confirmed_session is not None:
        try:
            confirmed_session.run(f"touch {shlex.quote(rollback_dir + '/confirmed')}", label="подтверждение Wi-Fi")
        finally:
            confirmed_session.close()
        progress("reconnect", "done", "Wi‑Fi подтверждён, автоматический откат отменён")
        return {
            "operation": "wifi_create" if creating else "wifi_edit",
            "section": target_section,
            "ssid": ssid,
            "radio": radio,
            "country": country,
            "password_changed": password_changed,
        }

    rolled_back = _confirm_router_rollback(
        spec,
        expected_fingerprint,
        "/etc/config/wireless",
        capability.get("config_sha256", ""),
        session_factory=session_factory,
    )
    raise SetupError(
        "wifi_reconnect_timeout",
        "Не удалось подтвердить новую Wi‑Fi сеть. Роутер вернул прежние настройки, если таймер отката завершился.",
        {"rolled_back": rolled_back},
    )


def change_lan_ip(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    new_ip: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    operation_id = _new_backup_id(session.fingerprint)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    try:
        current = _simple_key_values(
            session.run(
                "printf 'ipaddr=%s\\nnetmask=%s\\nproto=%s\\n' \"$(uci -q get network.lan.ipaddr)\" "
                "\"$(uci -q get network.lan.netmask || echo 255.255.255.0)\" \"$(uci -q get network.lan.proto)\"; "
                "command -v start-stop-daemon >/dev/null 2>&1 && echo rollback=1 || echo rollback=0; "
                "command -v sha256sum >/dev/null 2>&1 && echo sha256=1 || echo sha256=0; "
                "sha256sum /etc/config/network 2>/dev/null | awk '{print \"config_sha256=\" $1}'",
                label="проверка безопасной настройки LAN",
                check=False,
            )
        )
        if current.get("proto") not in {"static", ""} or current.get("rollback") != "1" or current.get("sha256") != "1":
            raise SetupError("lan_rollback_unavailable", "Текущую LAN-сеть нельзя безопасно изменить с автоматическим откатом.")
        new_ip = validate_lan_ip(new_ip, current.get("netmask") or "255.255.255.0")
        old_ip = current.get("ipaddr") or spec.host
        if new_ip == old_ip:
            raise SetupError("lan_ip_unchanged", "Новый локальный IP совпадает с текущим.")
        progress("rollback", "running", "Включаем автоматический откат LAN через две минуты")
        session.run(build_lan_rollback_command(operation_id), label="таймер отката LAN", timeout=20)
        progress("lan", "running", "Меняем локальный IP. Подключение к роутеру временно прервётся")
        try:
            session.run(
                f"uci set network.lan.ipaddr={shlex.quote(new_ip)}; uci commit network; /etc/init.d/network reload",
                label="изменение LAN IP",
                timeout=30,
                check=False,
            )
        except SetupError as exc:
            if exc.code != "ssh_command":
                raise
    finally:
        session.close()

    new_spec = ConnectionSpec(new_ip, spec.username, spec.password, spec.subscription_url, spec.port)
    verified_session = _wait_for_verified_router(
        new_spec,
        expected_fingerprint,
        "uci -q get network.lan.ipaddr",
        "проверка нового LAN IP",
        lambda value: value.strip() == new_ip,
        timeout_seconds=NETWORK_ROLLBACK_SECONDS + 12,
        session_factory=session_factory,
        sleep=sleep,
    )
    if verified_session is not None:
        try:
            verified_session.run(f"touch {shlex.quote(rollback_dir + '/confirmed')}", label="подтверждение LAN IP")
        finally:
            verified_session.close()
        progress("lan", "done", "Новый локальный IP подтверждён")
        return {"operation": "lan_ip", "old_ip": old_ip, "new_ip": new_ip}

    rolled_back = _confirm_router_rollback(
        spec,
        expected_fingerprint,
        "/etc/config/network",
        current.get("config_sha256", ""),
        session_factory=session_factory,
    )
    raise SetupError(
        "lan_reconnect_timeout",
        "Не удалось подтвердить новый локальный IP. Роутер вернул прежний адрес, если таймер отката завершился.",
        {"rolled_back": rolled_back, "old_ip": old_ip},
    )


def change_router_password(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    new_password: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    new_password = validate_router_password(new_password)
    if new_password == spec.password:
        raise SetupError("router_password_unchanged", "Новый пароль совпадает с текущим.")
    username = _validate_username(spec.username)
    session = _connect_pinned(spec, expected_fingerprint, session_factory)
    operation_id = _new_backup_id(session.fingerprint)
    rollback_dir = f"{ROUTER_ROLLBACK_ROOT}/{operation_id}"
    rollback_armed = False
    try:
        capability = _simple_key_values(
            session.run(
                "printf 'uid=%s\\n' \"$(id -u 2>/dev/null || echo unknown)\"; "
                "command -v start-stop-daemon >/dev/null 2>&1 && echo rollback=1 || echo rollback=0; "
                "command -v passwd >/dev/null 2>&1 && echo passwd=1 || echo passwd=0; "
                "[ -r /etc/shadow ] && [ -w /etc/shadow ] && echo shadow=1 || echo shadow=0; "
                "sha256sum /etc/shadow 2>/dev/null | awk '{print \"shadow_sha256=\" $1}'",
                label="проверка безопасной смены пароля",
                check=False,
            )
        )
        if capability.get("uid") != "0":
            raise SetupError("router_password_root_required", "Сменить пароль можно только при подключении с правами root.")
        if capability.get("rollback") != "1" or capability.get("passwd") != "1" or capability.get("shadow") != "1":
            raise SetupError("router_password_rollback_unavailable", "Роутер не подтвердил безопасную смену пароля с автоматическим откатом.")

        session.write_file("/tmp/kato-router-password", new_password.encode("utf-8"), mode="600")
        progress("rollback", "running", "Включаем автоматический откат пароля через две минуты")
        session.run(build_router_password_rollback_command(operation_id), label="таймер отката пароля", timeout=20)
        rollback_armed = True
        progress("password", "running", "Меняем пароль и проверяем новый SSH-вход")
        password_command = (
            "set -eu; new=$(cat /tmp/kato-router-password); "
            f"if command -v chpasswd >/dev/null 2>&1; then printf '%s:%s\\n' {shlex.quote(username)} \"$new\" | chpasswd; "
            f"else {{ printf '%s\\n' \"$new\"; printf '%s\\n' \"$new\"; }} | passwd {shlex.quote(username)}; fi; "
            "rm -f /tmp/kato-router-password"
        )
        session.run(password_command, label="смена пароля роутера", timeout=30)
    except Exception:
        if not rollback_armed:
            session.run("rm -f /tmp/kato-router-password", label="очистка временного пароля", check=False)
        raise
    finally:
        session.close()

    new_spec = ConnectionSpec(spec.host, username, new_password, spec.subscription_url, spec.port)
    verified_session = _wait_for_verified_router(
        new_spec,
        expected_fingerprint,
        "id -un",
        "проверка нового пароля",
        lambda value: value.strip() == username,
        timeout_seconds=NETWORK_ROLLBACK_SECONDS + 12,
        session_factory=session_factory,
        sleep=sleep,
    )
    if verified_session is not None:
        try:
            verified_session.run(
                f"touch {shlex.quote(rollback_dir + '/confirmed')}",
                label="подтверждение нового пароля",
            )
        finally:
            verified_session.close()
        progress("password", "done", "Новый пароль подтверждён")
        return {"operation": "router_password", "username": username}

    rolled_back = _confirm_router_rollback(
        spec,
        expected_fingerprint,
        "/etc/shadow",
        capability.get("shadow_sha256", ""),
        session_factory=session_factory,
    )
    raise SetupError(
        "router_password_reconnect_timeout",
        "Новый пароль не подтвердился. После завершения таймера роутер должен вернуть прежний пароль.",
        {"rolled_back": rolled_back},
    )


def _apply_command() -> str:
    return (
        "set -eu; "
        "/etc/init.d/nikki stop >/dev/null 2>&1 || true; "
        "uci -q import nikki < /tmp/kato-nikki-profile.uci; "
        "api_secret=$(tr -d '-' < /proc/sys/kernel/random/uuid); "
        "auth_password=$(tr -d '-' < /proc/sys/kernel/random/uuid); "
        "uci set nikki.mixin.api_secret=\"$api_secret\"; "
        "uci set nikki.@authentication[0].password=\"$auth_password\"; "
        "sid=$(uci add nikki subscription); "
        f"uci set nikki.$sid.name={shlex.quote(PROFILE_NAME)}; "
        "uci set nikki.$sid.url=\"$(cat /tmp/kato-subscription-url)\"; "
        f"uci set nikki.$sid.user_agent={shlex.quote(USER_AGENT)}; "
        "uci set nikki.$sid.prefer='remote'; "
        "uci set nikki.$sid.success='0'; "
        "uci set nikki.config.profile=\"subscription:$sid\"; "
        "uci set nikki.config.enabled='1'; "
        "uci commit nikki; "
        "printf '%s' \"$sid\""
    )


def _restore_backup_contents(
    session: RemoteSession,
    backup_dir: str,
    original_enabled: str,
    *,
    label: str,
) -> None:
    failed_root = f"/tmp/katovpn-nikki-displaced-{secrets.token_hex(4)}"
    command = (
        "set -eu; /etc/init.d/nikki stop >/dev/null 2>&1 || true; "
        f"mkdir -p {shlex.quote(failed_root)}; "
        f"cp -p {shlex.quote(backup_dir + '/nikki.uci')} /etc/config/nikki; "
        f"[ ! -d /etc/nikki/subscriptions ] || mv /etc/nikki/subscriptions {shlex.quote(failed_root + '/subscriptions')}; "
        f"[ ! -d {shlex.quote(backup_dir + '/subscriptions')} ] || cp -a {shlex.quote(backup_dir + '/subscriptions')} /etc/nikki/subscriptions; "
        f"[ ! -d /etc/nikki/profiles ] || mv /etc/nikki/profiles {shlex.quote(failed_root + '/profiles')}; "
        f"[ ! -d {shlex.quote(backup_dir + '/profiles')} ] || cp -a {shlex.quote(backup_dir + '/profiles')} /etc/nikki/profiles; "
        f"[ ! -f /etc/nikki/mixin.yaml ] || mv /etc/nikki/mixin.yaml {shlex.quote(failed_root + '/mixin.yaml')}; "
        f"[ ! -f {shlex.quote(backup_dir + '/mixin.yaml')} ] || cp -p {shlex.quote(backup_dir + '/mixin.yaml')} /etc/nikki/mixin.yaml; "
        + ("/etc/init.d/nikki start >/dev/null 2>&1" if original_enabled == "1" else "/etc/init.d/nikki stop >/dev/null 2>&1 || true")
    )
    session.run(command, label=label, timeout=60)


def _rollback(session: RemoteSession, backup_dir: str, original_enabled: str, progress: ProgressCallback) -> None:
    progress("rollback", "running", "Возвращаем предыдущую конфигурацию Nikki")
    _restore_backup_contents(session, backup_dir, original_enabled, label="автоматический откат")
    progress("rollback", "done", "Предыдущая конфигурация восстановлена")


def _update_router_components(
    session: RemoteSession,
    *,
    update_nikki: bool,
    update_mihomo: bool,
    progress: ProgressCallback,
    package_fetcher: Callable[[str, str | None], dict[str, Any]],
    mark_mutation: Callable[[], None] = lambda: None,
) -> dict[str, Any]:
    if not update_nikki and not update_mihomo:
        return {"nikki": None, "mihomo": None}

    progress("component_update", "running", "Готовим выбранные обновления")
    board_raw = session.run("ubus call system board", label="метаданные обновления")
    try:
        board = json.loads(board_raw)
    except json.JSONDecodeError as exc:
        raise SetupError("update_metadata", "Не удалось повторно определить совместимый комплект обновления.") from exc
    release = board.get("release", {}) if isinstance(board, Mapping) else {}
    firmware_version = str(release.get("version", ""))
    packages_raw = session.run(
        _installed_package_status_command(("nikki", "luci-app-nikki", "mihomo-meta", "mihomo-alpha", "mihomo")),
        label="пакеты обновления",
        check=False,
    )
    mihomo_meta_version = _package_version(packages_raw, "mihomo-meta")
    mihomo_alpha_version = _package_version(packages_raw, "mihomo-alpha")
    mihomo_legacy_version = _package_version(packages_raw, "mihomo")
    mihomo_package = "mihomo-meta" if mihomo_meta_version else "mihomo-alpha" if mihomo_alpha_version else None
    package_arch = (
        _package_field(packages_raw, mihomo_package, "Architecture") if mihomo_package else None
    ) or _package_field(packages_raw, "mihomo", "Architecture") or _package_field(packages_raw, "nikki", "Architecture")
    manager = session.run(
        "if command -v opkg >/dev/null 2>&1; then echo opkg; "
        "elif command -v apk >/dev/null 2>&1; then echo apk; else echo unknown; fi",
        label="пакетный менеджер обновления",
        check=False,
    ).strip()
    if manager not in {"opkg", "apk"}:
        raise SetupError(
            "update_manager_unsupported",
            "На роутере не найден поддерживаемый пакетный менеджер OpenWrt.",
        )

    feed = package_fetcher(firmware_version, package_arch)
    feed_url = str(feed.get("url") or "")
    parsed_feed = urllib.parse.urlsplit(feed_url)
    versions = feed.get("packages", {})
    if (
        feed.get("status") != "available"
        or parsed_feed.scheme.lower() != "https"
        or parsed_feed.hostname != "nikkinikki.pages.dev"
        or not parsed_feed.path.endswith("/index.json")
        or not isinstance(versions, Mapping)
        or not package_arch
        or not re.fullmatch(r"[A-Za-z0-9_+.-]{1,80}", package_arch)
    ):
        raise SetupError("update_source_unavailable", "Официальный совместимый комплект Nikki сейчас недоступен.")

    selected: list[tuple[str, str, str]] = []
    if update_mihomo:
        mihomo_runtime = session.run(
            "if command -v mihomo >/dev/null 2>&1; then mihomo -v 2>/dev/null | head -n 1; "
            "elif [ -x /usr/libexec/mihomo ]; then /usr/libexec/mihomo -v 2>/dev/null | head -n 1; "
            "else echo unknown; fi",
            label="версия Mihomo перед обновлением",
            check=False,
        )
        if mihomo_package not in {"mihomo-meta", "mihomo-alpha"}:
            mihomo_package = "mihomo-meta"
        version = str(versions.get(mihomo_package, ""))
        if not re.fullmatch(r"[A-Za-z0-9._+~:-]{1,100}", version):
            raise SetupError("mihomo_update_unavailable", "Для этого роутера не найден совместимый Mihomo Core.")
        installed_core = _semver(_semver_text(mihomo_runtime) or _semver_text(mihomo_meta_version or mihomo_alpha_version or mihomo_legacy_version))
        target_core = _semver(_semver_text(version))
        if not installed_core or not target_core or target_core <= installed_core:
            raise SetupError("mihomo_update_no_longer_available", "Версия Mihomo Core в официальном комплекте больше не новее установленной. Обновление остановлено.")
        selected.append((mihomo_package, version, package_arch))
    if update_nikki:
        installed_luci = _semver(_semver_text(_package_version(packages_raw, "luci-app-nikki")))
        target_luci = _semver(_semver_text(str(versions.get("luci-app-nikki", ""))))
        if not installed_luci or not target_luci or target_luci <= installed_luci:
            raise SetupError("nikki_update_no_longer_available", "Версия Nikki в официальном комплекте больше не новее установленной. Обновление остановлено.")
        for name, architecture in (("nikki", package_arch), ("luci-app-nikki", "all")):
            version = str(versions.get(name, ""))
            if not re.fullmatch(r"[A-Za-z0-9._+~:-]{1,100}", version):
                raise SetupError("nikki_update_unavailable", "Для этого роутера не найден совместимый пакет Nikki.")
            selected.append((name, version, architecture))

    package_root = feed_url[: -len("/index.json")]
    install_files: list[str] = []
    if manager == "opkg":
        download_parts = ["set -eu", "rm -f /tmp/kato-update-*.ipk"]
        for index, (name, version, architecture) in enumerate(selected):
            filename = f"{name}_{version}_{architecture}.ipk"
            if not re.fullmatch(r"[A-Za-z0-9._+~-]{1,220}", filename):
                raise SetupError("unsafe_update_package", "Имя пакета обновления отклонено проверкой безопасности.")
            local_path = f"/tmp/kato-update-{index}.ipk"
            download_parts.append(f"wget -q -O {shlex.quote(local_path)} {shlex.quote(package_root + '/' + filename)}")
            download_parts.append(f"test -s {shlex.quote(local_path)}")
            install_files.append(local_path)
        session.run("; ".join(download_parts), label="загрузка обновлений", timeout=180)
        dry_run_command = "opkg --noaction install " + " ".join(shlex.quote(path) for path in install_files)
    else:
        repository_url = package_root + "/packages.adb"
        selected_names = " ".join(shlex.quote(name) for name, _version, _architecture in selected)
        session.run("apk update", label="загрузка обновлений", timeout=180)
        dry_run_command = (
            "apk add --simulate --allow-untrusted --no-cache -X "
            + shlex.quote(repository_url)
            + " "
            + selected_names
        )

    dry_run_raw = session.run(
        "set +e; output=$(" + dry_run_command + " 2>&1); code=$?; printf '%s\\n' \"$output\"; "
        "printf '__KATO_PACKAGE_EXIT__=%s\\n' \"$code\"; exit 0",
        label="проверка установки обновлений",
        timeout=180,
        check=False,
    )
    dry_run_match = re.search(r"^__KATO_(?:PACKAGE|OPKG)_EXIT__=(\d+)$", dry_run_raw, re.MULTILINE)
    if not dry_run_match or int(dry_run_match.group(1)) != 0:
        session.run(
            "rm -f /tmp/kato-update-*.ipk",
            label="очистка пакетов обновления",
            check=False,
        )
        details: dict[str, Any] = {
            "stage": "package_dry_run",
            "package_install_started": False,
            "package_diagnostic": package_manager_failure_diagnostic(dry_run_raw, manager),
        }
        space_match = re.search(
            r"Only have\s+(\d+)kb.+?needs\s+(\d+)",
            dry_run_raw,
            re.IGNORECASE | re.DOTALL,
        )
        if space_match or re.search(r"not enough space|no space left", dry_run_raw, re.IGNORECASE):
            if space_match:
                details.update(
                    {
                        "available_overlay_kb": int(space_match.group(1)),
                        "required_overlay_kb": int(space_match.group(2)),
                    }
                )
            raise SetupError(
                "component_update_insufficient_space",
                "На overlay недостаточно места для выбранных пакетов. Nikki не останавливался, пакеты не изменены.",
                details,
            )
        raise SetupError(
            "component_update_precheck_failed",
            "Пакетный менеджер отклонил выбранные пакеты до установки. Nikki не останавливался, пакеты не изменены.",
            details,
        )

    mark_mutation()
    session.run(
        "/etc/init.d/nikki stop >/dev/null 2>&1 || true",
        label="остановка Nikki",
        timeout=75,
    )
    package_paths = {name: install_files[index] for index, (name, _version, _architecture) in enumerate(selected)} if manager == "opkg" else {}
    repository_url = package_root + "/packages.adb"
    if update_mihomo:
        command = (
            "opkg install " + shlex.quote(package_paths[mihomo_package])
            if manager == "opkg"
            else "apk add --allow-untrusted --no-cache -X " + shlex.quote(repository_url) + " " + shlex.quote(mihomo_package)
        )
        session.run(command, label="установка Mihomo Core", timeout=300)
    if update_nikki:
        command = (
            "opkg install " + " ".join(shlex.quote(package_paths[name]) for name in ("nikki", "luci-app-nikki"))
            if manager == "opkg"
            else "apk add --allow-untrusted --no-cache -X "
            + shlex.quote(repository_url)
            + " nikki luci-app-nikki"
        )
        session.run(command, label="установка Nikki", timeout=300)
    verify_package_names = tuple(name for name, _version, _arch in selected)
    verified_raw = session.run(
        _verify_installed_versions_command(manager, verify_package_names),
        label="проверка обновления компонентов",
        timeout=45,
    )
    verified = dict(line.split("=", 1) for line in verified_raw.splitlines() if "=" in line)
    for name, expected, _architecture in selected:
        if verified.get(name) != expected:
            raise SetupError(
                "component_update_verification",
                f"Пакет {name} не подтвердил ожидаемую версию {expected}.",
            )
    session.run("rm -f /tmp/kato-update-*.ipk", label="очистка пакетов обновления", check=False)
    progress("component_update", "done", "Выбранные компоненты обновлены и проверены")
    return {
        "nikki": _semver_text(str(versions.get("luci-app-nikki", ""))) if update_nikki else None,
        "mihomo": _semver_text(str(versions.get(mihomo_package, ""))) if update_mihomo else None,
    }


def update_router_components(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    update_nikki: bool,
    update_mihomo: bool,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    package_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_latest_nikki_packages,
) -> dict[str, Any]:
    """Update Nikki packages without importing or replacing the active profile."""
    if not update_nikki and not update_mihomo:
        raise SetupError("component_update_required", "Выберите хотя бы один компонент для обновления.")

    session = session_factory(spec)
    backup_dir = ""
    original_enabled = "0"
    mutation_started = False
    try:
        progress("connect", "running", "Подключаемся к подтверждённому роутеру")
        session.connect()
        if not expected_fingerprint or session.fingerprint != expected_fingerprint:
            raise SetupError("host_key_changed", "SSH-ключ роутера изменился после проверки. Обновление остановлено.")
        progress("connect", "done", "SSH-ключ совпадает с проверенным")

        original_enabled = session.run("uci -q get nikki.config.enabled || echo 0", label="исходное состояние", check=False) or "0"
        backup_id = _new_backup_id(session.fingerprint)
        backup_dir = f"{BACKUP_ROOT}/{backup_id}"
        progress("backup", "running", "Создаём backup текущих настроек Nikki")
        session.run(_backup_command(backup_dir, original_enabled), label="backup Nikki", timeout=45)
        progress("backup", "done", f"Backup сохранён: {backup_dir}")

        def mark_component_mutation() -> None:
            nonlocal mutation_started
            mutation_started = True

        component_updates = _update_router_components(
            session,
            update_nikki=update_nikki,
            update_mihomo=update_mihomo,
            progress=progress,
            package_fetcher=package_fetcher,
            mark_mutation=mark_component_mutation,
        )

        progress("restart", "running", "Запускаем Nikki после обновления")
        if original_enabled == "1":
            session.run("/etc/init.d/nikki start >/dev/null 2>&1", label="запуск Nikki после обновления", timeout=75)
            deadline = time.monotonic() + 50
            running = False
            while time.monotonic() < deadline:
                status = session.run("/etc/init.d/nikki status 2>/dev/null || true", label="статус Nikki", check=False)
                process = session.run("pidof mihomo >/dev/null 2>&1 && echo yes || echo no", label="процесс Mihomo", check=False)
                if "running" in status.lower() and process == "yes":
                    running = True
                    break
                time.sleep(2)
            if not running:
                raise SetupError("nikki_not_running_after_update", "Nikki/Mihomo не запустился после обновления.")
        else:
            session.run("/etc/init.d/nikki stop >/dev/null 2>&1 || true", label="сохранение выключенного состояния Nikki", check=False)
        progress("restart", "done", "Обновление проверено; настройки профиля не изменялись")

        session.run("rm -f /tmp/kato-update-*.ipk", label="очистка временных файлов", check=False)
        return {
            "status": "success",
            "operation": "update",
            "backup_path": backup_dir,
            "component_updates": component_updates,
            "profile_changed": False,
            "nikki_enabled": original_enabled == "1",
        }
    except Exception as exc:
        rollback_error: SetupError | None = None
        if backup_dir and mutation_started:
            try:
                _rollback(session, backup_dir, original_enabled, progress)
            except SetupError as rollback_exc:
                rollback_error = rollback_exc
        if isinstance(exc, SetupError):
            if rollback_error:
                raise SetupError(
                    "update_and_rollback_failed",
                    "Обновление не завершено, а восстановление настроек требует ручной проверки.",
                    {
                        "update": exc.as_dict(),
                        "rollback": rollback_error.as_dict(),
                        "backup_path": backup_dir,
                        "package_versions_rolled_back": False,
                    },
                ) from exc
            if backup_dir and mutation_started:
                exc.details.update(
                    {
                        "rolled_back": True,
                        "backup_path": backup_dir,
                        "package_versions_rolled_back": False,
                    }
                )
            raise
        raise SetupError("unexpected_update", "Обновление остановлено из-за непредвиденной ошибки.") from exc
    finally:
        try:
            session.run("rm -f /tmp/kato-update-*.ipk", label="очистка временных файлов", check=False)
        except Exception:
            pass
        session.close()


def install_router_vpn(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    subscription_fetcher: Callable[[str], dict[str, Any]] = fetch_and_validate_subscription,
    package_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_latest_nikki_packages,
    template_text: str | None = None,
) -> dict[str, Any]:
    """Install the exact official Nikki/Mihomo package set, then configure KatoVPN."""
    progress("validate", "running", "Проверяем подписку и профиль до установки")
    subscription_fetcher(spec.subscription_url)
    if template_text is None:
        template_text = profile_template_path().read_text(encoding="utf-8")
    validate_portable_template(template_text)
    progress("validate", "done", "Подписка и профиль готовы")

    session = session_factory(spec)
    package_install_started = False
    verified_versions: dict[str, str] = {}
    try:
        progress("connect", "running", "Повторно проверяем роутер перед установкой")
        session.connect()
        if not expected_fingerprint or not secrets.compare_digest(session.fingerprint, str(expected_fingerprint)):
            raise SetupError("host_key_changed", "SSH-ключ роутера изменился после проверки. Установка остановлена.")

        board_raw = session.run("ubus call system board", label="сведения для установки VPN")
        try:
            board = json.loads(board_raw)
        except json.JSONDecodeError as exc:
            raise SetupError("install_board_info", "Не удалось повторно определить версию OpenWrt.") from exc
        release = board.get("release", {}) if isinstance(board, Mapping) else {}
        firmware_version = str(release.get("version", ""))
        distribution = str(release.get("distribution") or release.get("description") or "").lower()

        readiness_raw = session.run(
            "mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo); "
            "free=$(df -Pk /overlay 2>/dev/null | awk 'NR==2 {print $4}'); "
            "for c in uci fw4 nft opkg apk; do command -v \"$c\" >/dev/null 2>&1 && echo \"$c=1\" || echo \"$c=0\"; done; "
            + _package_arch_probe()
            + "printf 'memory_kb=%s\\noverlay_free_kb=%s\\n' \"${mem:-0}\" \"${free:-0}\"; "
            "[ -w /overlay ] && echo overlay_writable=1 || echo overlay_writable=0; "
            "nslookup openwrt.org >/dev/null 2>&1 && echo dns=1 || echo dns=0; "
            "if command -v uclient-fetch >/dev/null 2>&1; then fetch='uclient-fetch -q -T 15 -O -'; "
            "elif command -v wget >/dev/null 2>&1; then fetch='wget -q -T 15 -O -'; "
            "elif command -v curl >/dev/null 2>&1; then fetch='curl -fsSL --max-time 15'; else fetch=''; fi; "
            "[ -n \"$fetch\" ] && $fetch https://openwrt.org/ >/dev/null 2>&1 && echo https=1 || echo https=0; "
            "[ -n \"$fetch\" ] && $fetch https://nikkinikki.pages.dev/ >/dev/null 2>&1 && echo feed=1 || echo feed=0",
            label="готовность установки VPN",
            timeout=55,
            check=False,
        )
        readiness = _simple_key_values(readiness_raw)

        def number(key: str) -> int:
            try:
                return max(0, int(readiness.get(key, "0")))
            except ValueError:
                return 0

        blockers: list[str] = []
        if not any(name in distribution for name in ("openwrt", "immortalwrt")) or _parse_version_pair(firmware_version) < (24, 10):
            blockers.append("Нужен OpenWrt/ImmortalWrt 24.10 или новее.")
        package_manager = "opkg" if readiness.get("opkg") == "1" else "apk" if readiness.get("apk") == "1" else "unknown"
        if any(readiness.get(name) != "1" for name in ("uci", "fw4", "nft")) or package_manager == "unknown":
            blockers.append("Не найдены пакетный менеджер OpenWrt, UCI или firewall4/nftables.")
        if number("memory_kb") < VPN_INSTALL_MIN_RAM_KB:
            blockers.append("Для VPN-модуля нужно не менее 200 МБ доступной оперативной памяти.")
        if number("overlay_free_kb") < VPN_INSTALL_MIN_OVERLAY_KB:
            blockers.append("Для установки нужно не менее 64 МБ свободного места на overlay.")
        if readiness.get("overlay_writable") != "1":
            blockers.append("Системный раздел роутера доступен только для чтения.")
        if readiness.get("dns") != "1" or readiness.get("https") != "1" or readiness.get("feed") != "1":
            blockers.append("Роутер не может скачать официальный VPN-модуль по HTTPS.")
        package_arch = readiness.get("package_arch", "")
        if not re.fullmatch(r"[A-Za-z0-9_+.-]{1,80}", package_arch):
            blockers.append("Не удалось определить архитектуру пакетов роутера.")
        if blockers:
            raise SetupError("vpn_install_incompatible", "Установка VPN-модуля недоступна.", {"blockers": blockers})
        progress("connect", "done", "Роутер повторно проверен")

        feed = package_fetcher(firmware_version, package_arch)
        feed_url = str(feed.get("url") or "")
        parsed_feed = urllib.parse.urlsplit(feed_url)
        versions = feed.get("packages", {})
        if (
            feed.get("status") != "available"
            or parsed_feed.scheme.lower() != "https"
            or parsed_feed.hostname != "nikkinikki.pages.dev"
            or not parsed_feed.path.endswith("/index.json")
            or not isinstance(versions, Mapping)
            or not {"nikki", "luci-app-nikki", "mihomo-meta"}.issubset(versions)
        ):
            raise SetupError("vpn_install_source_unavailable", "Официальный совместимый комплект VPN-модуля сейчас недоступен.")

        selected = (
            ("mihomo-meta", str(versions["mihomo-meta"]), package_arch),
            ("nikki", str(versions["nikki"]), package_arch),
            ("luci-app-nikki", str(versions["luci-app-nikki"]), "all"),
        )
        package_root = feed_url[: -len("/index.json")]
        install_files: list[str] = []
        for name, version, _architecture in selected:
            if not re.fullmatch(r"[A-Za-z0-9._+~:-]{1,100}", version):
                raise SetupError("vpn_install_package_invalid", "Официальный индекс вернул некорректную версию пакета.")

        progress("packages", "running", "Обновляем список и проверяем официальный комплект")
        if package_manager == "opkg":
            download_parts = ["set -eu", "rm -f /tmp/kato-install-*.ipk"]
            for index, (name, version, architecture) in enumerate(selected):
                filename = f"{name}_{version}_{architecture}.ipk"
                if not re.fullmatch(r"[A-Za-z0-9._+~-]{1,220}", filename):
                    raise SetupError("vpn_install_package_invalid", "Имя пакета отклонено проверкой безопасности.")
                local_path = f"/tmp/kato-install-{index}.ipk"
                package_url = package_root + "/" + filename
                download_parts.append(
                    "if command -v uclient-fetch >/dev/null 2>&1; then "
                    f"uclient-fetch -q -T 90 -O {shlex.quote(local_path)} {shlex.quote(package_url)}; "
                    "elif command -v wget >/dev/null 2>&1; then "
                    f"wget -q -T 90 -O {shlex.quote(local_path)} {shlex.quote(package_url)}; "
                    "elif command -v curl >/dev/null 2>&1; then "
                    f"curl -fsSL --connect-timeout 10 --max-time 90 -o {shlex.quote(local_path)} {shlex.quote(package_url)}; "
                    "else exit 127; fi"
                )
                download_parts.append(f"test -s {shlex.quote(local_path)}")
                install_files.append(local_path)
            session.run("opkg update", label="обновление списка пакетов VPN", timeout=180)
            session.run("; ".join(download_parts), label="загрузка VPN-модуля", timeout=300)
            install_arguments = " ".join(
                [*(shlex.quote(name) for name in VPN_INSTALL_DEPENDENCIES), *(shlex.quote(path) for path in install_files)]
            )
            dry_run_command = "opkg --noaction install " + install_arguments
            install_command = "opkg install " + install_arguments
        else:
            repository_url = package_root + "/packages.adb"
            install_arguments = "mihomo-meta nikki luci-app-nikki"
            session.run("apk update", label="обновление списка пакетов VPN", timeout=180)
            dry_run_command = (
                "apk add --simulate --allow-untrusted --no-cache -X "
                + shlex.quote(repository_url)
                + " "
                + install_arguments
            )
            install_command = (
                "apk add --allow-untrusted --no-cache -X "
                + shlex.quote(repository_url)
                + " "
                + install_arguments
            )
        dry_run_raw = session.run(
            "set +e; output=$(" + dry_run_command + " 2>&1); code=$?; "
            "printf '%s\\n' \"$output\"; printf '__KATO_PACKAGE_EXIT__=%s\\n' \"$code\"; exit 0",
            label="проверка установки VPN",
            timeout=300,
            check=False,
        )
        dry_run_match = re.search(r"^__KATO_(?:PACKAGE|OPKG)_EXIT__=(\d+)$", dry_run_raw, re.MULTILINE)
        if not dry_run_match or int(dry_run_match.group(1)) != 0:
            details: dict[str, Any] = {
                "stage": "package_dry_run",
                "package_install_started": False,
                "package_diagnostic": package_manager_failure_diagnostic(dry_run_raw, package_manager),
            }
            space_match = re.search(r"Only have\s+(\d+)kb.+?needs\s+(\d+)", dry_run_raw, re.IGNORECASE | re.DOTALL)
            if space_match:
                details.update({"available_overlay_kb": int(space_match.group(1)), "required_overlay_kb": int(space_match.group(2))})
            if space_match or re.search(r"not enough space|no space left", dry_run_raw, re.IGNORECASE):
                raise SetupError("vpn_install_insufficient_space", "На роутере недостаточно места. Пакеты не изменены.", details)
            raise SetupError("vpn_install_precheck_failed", "Пакетный менеджер отклонил комплект до установки. Пакеты не изменены.", details)

        package_install_started = True
        session.run(install_command, label="установка VPN-модуля", timeout=600)
        verify_package_names = tuple(name for name, _version, _arch in selected)
        verified_raw = session.run(
            _verify_installed_versions_command(package_manager, verify_package_names),
            label="проверка пакетов VPN",
            timeout=60,
        )
        verified_versions = _simple_key_values(verified_raw)
        for name, expected, _architecture in selected:
            if verified_versions.get(name) != expected:
                raise SetupError(
                    "vpn_install_verification",
                    f"Пакет {name} не подтвердил ожидаемую версию {expected}.",
                    {"package_install_started": True, "packages_installed": True},
                )
        files_ready = session.run(
            "[ -x /etc/init.d/nikki ] && [ -s /etc/config/nikki ] && "
            "(command -v mihomo >/dev/null 2>&1 || [ -x /usr/libexec/mihomo ] || [ -x /usr/bin/mihomo ]) "
            "&& echo ready || echo missing",
            label="проверка файлов VPN",
            check=False,
        )
        if files_ready.strip() != "ready":
            raise SetupError(
                "vpn_install_runtime_missing",
                "Пакеты установлены, но файлы Nikki/Mihomo не прошли проверку.",
                {"package_install_started": True, "packages_installed": True},
            )
        progress("packages", "done", "VPN-модуль установлен и проверен")
    except SetupError as exc:
        if package_install_started:
            exc.details.setdefault("package_install_started", True)
            exc.details.setdefault("packages_installed", bool(verified_versions))
        raise
    except Exception as exc:
        raise SetupError(
            "unexpected_vpn_install",
            "Установка VPN-модуля остановлена из-за непредвиденной ошибки.",
            {"package_install_started": package_install_started},
        ) from exc
    finally:
        try:
            session.run("rm -f /tmp/kato-install-*.ipk", label="очистка установки VPN", check=False)
        except Exception:
            pass
        session.close()

    try:
        configured = configure_router(
            spec,
            expected_fingerprint,
            progress=progress,
            session_factory=session_factory,
            subscription_fetcher=subscription_fetcher,
            package_fetcher=package_fetcher,
            template_text=template_text,
        )
    except SetupError as exc:
        exc.details.setdefault("packages_installed", True)
        exc.details.setdefault("installed_versions", dict(verified_versions))
        raise
    return {
        **configured,
        "operation": "install",
        "packages_installed": True,
        "installed_versions": dict(verified_versions),
    }


def replace_router_subscription(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    subscription_fetcher: Callable[[str], dict[str, Any]] = fetch_and_validate_subscription,
) -> dict[str, Any]:
    """Replace the URL of the active Nikki subscription without touching packages."""
    progress("validate", "running", "Проверяем новую ссылку подписки")
    subscription_fetcher(spec.subscription_url)
    progress("validate", "done", "Подписка совместима с профилем KatoVPN")

    session = session_factory(spec)
    backup_dir = ""
    original_enabled = "0"
    mutation_started = False
    sid = ""
    try:
        progress("connect", "running", "Подключаемся к подтверждённому роутеру")
        session.connect()
        if not expected_fingerprint or session.fingerprint != expected_fingerprint:
            raise SetupError(
                "host_key_changed",
                "SSH-ключ роутера изменился после проверки. Смена ссылки остановлена.",
            )
        progress("connect", "done", "SSH-ключ совпадает с проверенным")

        sid = session.run(
            "profile=$(uci -q get nikki.config.profile); case \"$profile\" in subscription:*) "
            "printf '%s' \"${profile#subscription:}\";; esac",
            label="active Nikki subscription",
            check=False,
        )
        if not re.fullmatch(r"cfg[0-9a-fA-F]+|[A-Za-z0-9_-]+", sid):
            raise SetupError(
                "active_subscription_required",
                "В Nikki не выбран профиль подписки. Сначала установите профиль KatoVPN.",
            )

        original_enabled = session.run(
            "uci -q get nikki.config.enabled || echo 0",
            label="исходное состояние",
            check=False,
        ) or "0"
        backup_id = _new_backup_id(session.fingerprint)
        backup_dir = f"{BACKUP_ROOT}/{backup_id}"
        progress("backup", "running", "Создаём backup текущих настроек Nikki")
        session.run(_backup_command(backup_dir, original_enabled), label="backup Nikki", timeout=45)
        progress("backup", "done", f"Backup сохранён: {backup_dir}")

        progress("subscription", "running", "Сохраняем и загружаем новую подписку")
        session.write_file("/tmp/kato-subscription-url", spec.subscription_url.encode("utf-8"))
        mutation_started = True
        quoted_sid = shlex.quote(sid)
        session.run(
            "set -eu; sid=" + quoted_sid + "; "
            "uci set nikki.$sid.url=\"$(cat /tmp/kato-subscription-url)\"; "
            f"uci set nikki.$sid.user_agent={shlex.quote(USER_AGENT)}; "
            "uci set nikki.$sid.success='0'; uci commit nikki",
            label="save subscription URL",
            timeout=30,
        )
        session.run(
            f"/etc/init.d/nikki update_subscription {quoted_sid}",
            label="refresh subscription",
            timeout=180,
        )
        refresh_success = session.run(
            f"uci -q get nikki.{quoted_sid}.success || echo 0",
            label="subscription download result",
            check=False,
        )
        if refresh_success != "1":
            raise SetupError(
                "subscription_refresh_failed",
                "Nikki не смог загрузить новую подписку. Предыдущая ссылка будет восстановлена.",
            )
        profile_info = validate_subscription_document(
            session.read_file(f"/etc/nikki/subscriptions/{sid}.yaml")
        )

        if original_enabled == "1":
            session.run(
                "/etc/init.d/nikki reload >/dev/null 2>&1",
                label="reload Nikki profile",
                timeout=75,
            )
            status = session.run(
                "/etc/init.d/nikki status 2>/dev/null || true",
                label="статус Nikki",
                check=False,
            )
            process = session.run(
                "pidof mihomo >/dev/null 2>&1 && echo yes || echo no",
                label="процесс Mihomo",
                check=False,
            )
            if "running" not in status.lower() or process != "yes":
                raise SetupError(
                    "nikki_not_running_after_subscription_change",
                    "Nikki/Mihomo не запустился после смены подписки.",
                )
        active = session.run(
            "uci -q get nikki.config.profile",
            label="active profile after subscription change",
        )
        if active != f"subscription:{sid}":
            raise SetupError(
                "profile_verification",
                "После смены ссылки Nikki выбрал другой профиль.",
            )
        progress("subscription", "done", "Ссылка подписки обновлена и проверена")
        return {
            "status": "success",
            "operation": "subscription",
            "subscription_id": sid,
            "backup_path": backup_dir,
            "components_changed": False,
            "profile_changed": False,
            "subscription": profile_info,
            "nikki_enabled": original_enabled == "1",
        }
    except Exception as exc:
        rollback_error: SetupError | None = None
        if backup_dir and mutation_started:
            try:
                _rollback(session, backup_dir, original_enabled, progress)
            except SetupError as rollback_exc:
                rollback_error = rollback_exc
        if isinstance(exc, SetupError):
            if rollback_error:
                raise SetupError(
                    "subscription_and_rollback_failed",
                    "Ссылка не изменена, а восстановление настроек требует ручной проверки.",
                    {
                        "subscription": exc.as_dict(),
                        "rollback": rollback_error.as_dict(),
                        "backup_path": backup_dir,
                    },
                ) from exc
            if backup_dir and mutation_started:
                exc.details.update({"rolled_back": True, "backup_path": backup_dir})
            raise
        raise SetupError(
            "unexpected_subscription_change",
            "Смена ссылки остановлена из-за непредвиденной ошибки.",
        ) from exc
    finally:
        try:
            session.run(
                "rm -f /tmp/kato-subscription-url",
                label="очистка временных файлов",
                check=False,
            )
        except Exception:
            pass
        session.close()


def configure_router(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    subscription_fetcher: Callable[[str], dict[str, Any]] = fetch_and_validate_subscription,
    package_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_latest_nikki_packages,
    template_text: str | None = None,
    update_nikki: bool = False,
    update_mihomo: bool = False,
) -> dict[str, Any]:
    progress("validate", "running", "Повторно проверяем профиль перед изменением")
    subscription_fetcher(spec.subscription_url)
    if template_text is None:
        template_text = profile_template_path().read_text(encoding="utf-8")
    template_info = validate_portable_template(template_text)
    progress("validate", "done", "Шаблон и подписка прошли проверку")

    session = session_factory(spec)
    backup_dir = ""
    original_enabled = "0"
    mutation_started = False
    component_updates = {"nikki": None, "mihomo": None}
    sid = ""
    try:
        progress("connect", "running", "Подключаемся к подтверждённому роутеру")
        session.connect()
        if not expected_fingerprint or session.fingerprint != expected_fingerprint:
            raise SetupError("host_key_changed", "SSH-ключ роутера изменился после проверки. Применение остановлено.")
        progress("connect", "done", "SSH-ключ совпадает с проверенным")

        original_enabled = session.run("uci -q get nikki.config.enabled || echo 0", label="исходное состояние", check=False) or "0"
        backup_id = _new_backup_id(session.fingerprint)
        backup_dir = f"{BACKUP_ROOT}/{backup_id}"
        progress("backup", "running", "Создаём backup текущих настроек Nikki")
        session.run(_backup_command(backup_dir, original_enabled), label="backup Nikki", timeout=45)
        progress("backup", "done", f"Backup сохранён: {backup_dir}")

        if update_nikki or update_mihomo:
            def mark_component_mutation() -> None:
                nonlocal mutation_started
                mutation_started = True

            component_updates = _update_router_components(
                session,
                update_nikki=update_nikki,
                update_mihomo=update_mihomo,
                progress=progress,
                package_fetcher=package_fetcher,
                mark_mutation=mark_component_mutation,
            )

        progress("upload", "running", "Передаём обезличенный шаблон и ссылку")
        session.write_file("/tmp/kato-nikki-profile.uci", template_text.encode("utf-8"))
        session.write_file("/tmp/kato-subscription-url", spec.subscription_url.encode("utf-8"))
        progress("upload", "done", "Временные файлы переданы")

        progress("apply", "running", "Импортируем UCI и создаём профиль KatoVPN")
        mutation_started = True
        sid = session.run(_apply_command(), label="импорт настроек Nikki", timeout=45)
        if not re.fullmatch(r"cfg[0-9a-fA-F]+|[A-Za-z0-9_-]+", sid):
            raise SetupError("invalid_subscription_id", "Nikki вернул неожиданный ID профиля.")
        session.run("/etc/init.d/nikki start >/dev/null 2>&1", label="запуск Nikki", timeout=75)
        progress("apply", "done", "Профиль создан, Nikki запущен")

        progress("verify", "running", "Проверяем Mihomo, nftables, DNS и policy routing")
        deadline = time.monotonic() + 50
        running = False
        while time.monotonic() < deadline:
            status = session.run("/etc/init.d/nikki status 2>/dev/null || true", label="статус Nikki", check=False)
            process = session.run("pidof mihomo >/dev/null 2>&1 && echo yes || echo no", label="процесс Mihomo", check=False)
            if "running" in status.lower() and process == "yes":
                running = True
                break
            time.sleep(2)
        if not running:
            raise SetupError("nikki_not_running", "Nikki/Mihomo не запустился после применения.")

        profile_raw = session.read_file(f"/etc/nikki/subscriptions/{sid}.yaml")
        profile_info = validate_subscription_document(profile_raw)
        runtime_raw = session.read_file("/etc/nikki/run/config.yaml")
        runtime_info = validate_subscription_document(runtime_raw)

        nft = session.run("nft list table inet nikki 2>/dev/null", label="таблица nftables", timeout=20)
        if "chain lan_redirect" not in nft or "chain lan_tproxy" not in nft:
            raise SetupError("nft_verification", "В таблице nftables нет цепочек Redirect/TPROXY Nikki.")
        policy = session.run("ip -4 rule show", label="policy routing", check=False)
        if "fwmark 0x80/0xff lookup 80" not in policy:
            raise SetupError("routing_verification", "Не найдено policy-routing правило TPROXY 0x80/0xff.")
        dns = session.run(
            "if command -v ss >/dev/null 2>&1 && "
            "ss -H -lnup 2>/dev/null | grep -Eq '(:|\\])1053([[:space:]]|$)'; then echo listening; "
            "elif command -v netstat >/dev/null 2>&1 && "
            "netstat -lnu 2>/dev/null | grep -Eq '(:|\\])1053[[:space:]]'; then echo listening; "
            "elif awk '$2 ~ /:041D$/ { found=1 } END { exit !found }' /proc/net/udp /proc/net/udp6 2>/dev/null; "
            "then echo listening; fi",
            label="DNS listener",
            check=False,
        )
        if not dns:
            raise SetupError("dns_verification", "Mihomo не слушает DNS-порт 1053.")

        active = session.run("uci -q get nikki.config.profile", label="активный профиль")
        if active != f"subscription:{sid}":
            raise SetupError("profile_verification", "Nikki активировал другой профиль.")
        progress("verify", "done", "Redirect/TPROXY работает, TUN выключен")

        session.run(
            "rm -f /tmp/kato-nikki-profile.uci /tmp/kato-subscription-url /tmp/kato-update-*.ipk",
            label="очистка временных файлов",
            check=False,
        )
        return {
            "status": "success",
            "profile_name": PROFILE_NAME,
            "user_agent": USER_AGENT,
            "backup_path": backup_dir,
            "active_profile": active,
            "template": template_info,
            "subscription": profile_info,
            "runtime": runtime_info,
            "mode": "TCP Redirect + UDP TPROXY",
            "tun": False,
            "component_updates": component_updates,
        }
    except Exception as exc:
        rollback_error: SetupError | None = None
        if backup_dir and mutation_started:
            try:
                _rollback(session, backup_dir, original_enabled, progress)
            except SetupError as rollback_exc:
                rollback_error = rollback_exc
        if isinstance(exc, SetupError):
            if rollback_error:
                raise SetupError(
                    "apply_and_rollback_failed",
                    "Применение не удалось, автоматический откат тоже требует ручной проверки.",
                    {
                        "apply": exc.as_dict(),
                        "rollback": rollback_error.as_dict(),
                        "backup_path": backup_dir,
                        "package_versions_rolled_back": not (update_nikki or update_mihomo),
                    },
                ) from exc
            if backup_dir and mutation_started:
                exc.details.update(
                    {
                        "rolled_back": True,
                        "backup_path": backup_dir,
                        "package_versions_rolled_back": not (update_nikki or update_mihomo),
                    }
                )
            raise
        raise SetupError("unexpected_apply", "Настройка остановлена из-за непредвиденной ошибки.") from exc
    finally:
        if session:
            try:
                session.run(
                    "rm -f /tmp/kato-nikki-profile.uci /tmp/kato-subscription-url /tmp/kato-update-*.ipk",
                    label="очистка временных файлов",
                    check=False,
                )
            except Exception:
                pass
            session.close()


def restore_router_backup(
    spec: ConnectionSpec,
    expected_fingerprint: str,
    backup_id: str,
    *,
    progress: ProgressCallback = _noop_progress,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
) -> dict[str, Any]:
    backup_id = validate_backup_id(backup_id)
    selected_dir = f"{BACKUP_ROOT}/{backup_id}"
    session = session_factory(spec)
    safety_backup_dir = ""
    current_enabled = "0"
    mutation_started = False
    try:
        progress("connect", "running", "Подключаемся к подтверждённому роутеру")
        session.connect()
        if not expected_fingerprint or session.fingerprint != expected_fingerprint:
            raise SetupError("host_key_changed", "SSH-ключ роутера изменился после проверки. Восстановление остановлено.")
        progress("connect", "done", "SSH-ключ совпадает с проверенным")

        selected_enabled = session.run(
            f"set -eu; test -f {shlex.quote(selected_dir + '/nikki.uci')}; "
            f"value=$(cat {shlex.quote(selected_dir + '/original-enabled')}); "
            "case \"$value\" in 0|1) printf '%s' \"$value\" ;; *) exit 2 ;; esac",
            label="проверка backup",
        )
        if selected_enabled not in {"0", "1"}:
            raise SetupError("invalid_backup", "Backup Nikki неполный или повреждён.")

        current_enabled = session.run("uci -q get nikki.config.enabled || echo 0", label="исходное состояние", check=False) or "0"
        safety_backup_id = _new_backup_id(session.fingerprint)
        safety_backup_dir = f"{BACKUP_ROOT}/{safety_backup_id}"
        progress("backup", "running", "Сохраняем текущее состояние перед восстановлением")
        session.run(_backup_command(safety_backup_dir, current_enabled), label="backup Nikki", timeout=45)
        progress("backup", "done", f"Страховочный backup сохранён: {safety_backup_dir}")

        progress("restore", "running", f"Восстанавливаем backup {backup_id}")
        mutation_started = True
        _restore_backup_contents(session, selected_dir, selected_enabled, label="восстановление backup")
        progress("restore", "done", "Файлы и состояние Nikki восстановлены")

        progress("verify", "running", "Проверяем восстановленную конфигурацию")
        matched = session.run(
            f"cmp -s {shlex.quote(selected_dir + '/nikki.uci')} /etc/config/nikki && echo yes || echo no",
            label="проверка файла backup",
            check=False,
        )
        if matched != "yes":
            raise SetupError("restore_verification", "Восстановленный UCI-файл не совпал с выбранным backup.")

        if selected_enabled == "1":
            deadline = time.monotonic() + 40
            running = False
            while time.monotonic() < deadline:
                status = session.run("/etc/init.d/nikki status 2>/dev/null || true", label="статус Nikki", check=False)
                process = session.run("pgrep -x mihomo >/dev/null 2>&1 && echo yes || echo no", label="процесс Mihomo", check=False)
                if "running" in status.lower() and process == "yes":
                    running = True
                    break
                time.sleep(2)
            if not running:
                raise SetupError("restore_runtime", "Backup восстановлен, но Nikki/Mihomo не запустился.")
        else:
            process = session.run("pgrep -x mihomo >/dev/null 2>&1 && echo yes || echo no", label="процесс Mihomo", check=False)
            if process == "yes":
                raise SetupError("restore_runtime", "Backup должен оставить Nikki выключенным, но Mihomo продолжает работать.")
        progress("verify", "done", "Восстановленная конфигурация проверена")

        return {
            "status": "success",
            "operation": "restore",
            "restored_backup": selected_dir,
            "safety_backup_path": safety_backup_dir,
            "nikki_enabled": selected_enabled == "1",
        }
    except Exception as exc:
        rollback_error: SetupError | None = None
        if safety_backup_dir and mutation_started:
            try:
                _rollback(session, safety_backup_dir, current_enabled, progress)
            except SetupError as rollback_exc:
                rollback_error = rollback_exc
        if isinstance(exc, SetupError):
            if rollback_error:
                raise SetupError(
                    "restore_and_rollback_failed",
                    "Восстановление не удалось, возврат к состоянию перед восстановлением тоже требует ручной проверки.",
                    {
                        "restore": exc.as_dict(),
                        "rollback": rollback_error.as_dict(),
                        "safety_backup_path": safety_backup_dir,
                    },
                ) from exc
            if safety_backup_dir and mutation_started:
                exc.details.update({"rolled_back": True, "safety_backup_path": safety_backup_dir})
            raise
        raise SetupError("unexpected_restore", "Восстановление остановлено из-за непредвиденной ошибки.") from exc
    finally:
        session.close()
