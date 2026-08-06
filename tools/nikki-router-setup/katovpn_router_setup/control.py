from __future__ import annotations

import json
import ipaddress
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

import requests
import yaml

from .core import (
    MAX_SUBSCRIPTION_BYTES,
    USER_AGENT,
    ConnectionSpec,
    RemoteSession,
    SetupError,
    fetch_latest_nikki_packages,
)


MIN_RAM_KB = 200 * 1024
RECOMMENDED_RAM_KB = 512 * 1024
MIN_INSTALL_OVERLAY_KB = 64 * 1024
SUPPORTED_DISTRIBUTIONS = {"openwrt", "immortalwrt"}
HARDWARE_MUTATIONS_VALIDATED = False
ADBLOCK_CLASS_RAM_KB = 448 * 1024

NIKKI_DEPENDENCIES = [
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
]
NIKKI_PACKAGES = ["mihomo-meta", "nikki", "luci-app-nikki"]


def mask_subscription_url(value: str) -> str:
    """Keep enough of a URL to identify the provider without exposing its token."""
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() == "https" and parsed.hostname:
            port = f":{parsed.port}" if parsed.port else ""
            return f"https://{parsed.hostname}{port}/…"
    except (TypeError, ValueError):
        pass
    return "скрыта"


def _version_pair(value: str) -> tuple[int, int]:
    match = re.search(r"(\d+)\.(\d+)", value or "")
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _semantic_version(value: str | None) -> tuple[int, ...]:
    match = re.search(r"(?:^|\D)(\d+)\.(\d+)\.(\d+)(?:\D|$)", value or "")
    return tuple(int(part) for part in match.groups()) if match else ()


def _runtime_version(value: str) -> str | None:
    match = re.search(r"(?:^|\s)v?(\d+\.\d+\.\d+)(?:\s|$)", value or "")
    return match.group(1) if match else None


def _integer(values: Mapping[str, str], key: str) -> int:
    try:
        return max(0, int(values.get(key, "0")))
    except (TypeError, ValueError):
        return 0


def _key_values(raw: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def _package_blocks(raw: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for block in re.split(r"\n\s*\n", raw.strip()):
        fields = _key_values(block.replace(": ", "="))
        name = fields.get("Package") or fields.get("name")
        if name:
            result[name] = fields
    return result


def _country_flag(country_code: str) -> str:
    code = str(country_code).upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return ""
    return "".join(chr(127397 + ord(letter)) for letter in code)


def parse_public_ip_info(raw: str) -> dict[str, Any]:
    empty = {
        "available": False,
        "ip": None,
        "city": None,
        "region": None,
        "country_code": None,
        "country": None,
        "flag": "",
        "provider": None,
    }
    try:
        value = json.loads(raw) if raw else {}
        if not isinstance(value, Mapping):
            return empty
        address = str(ipaddress.ip_address(str(value.get("ip", ""))))
    except (json.JSONDecodeError, ValueError):
        return empty
    country_code = str(value.get("country_code") or "").upper()
    if not re.fullmatch(r"[A-Z]{2}", country_code):
        country_code = ""

    def clean(field: str, maximum: int = 120) -> str | None:
        text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value.get(field) or "")).strip()
        return text[:maximum] or None

    provider = clean("org", 160) or clean("asn", 80)
    return {
        "available": True,
        "ip": address,
        "city": clean("city"),
        "region": clean("region"),
        "country_code": country_code or None,
        "country": clean("country_name") or clean("country"),
        "flag": _country_flag(country_code),
        "provider": provider,
    }


def _subscription_userinfo(headers: Mapping[str, Any]) -> dict[str, Any]:
    raw = str(headers.get("subscription-userinfo") or headers.get("Subscription-Userinfo") or "")
    match = re.search(r"(?:^|[;\s])expire=(\d+)(?:$|[;\s])", raw, re.IGNORECASE)
    if not match:
        return {}
    try:
        epoch = int(match.group(1))
        if epoch < 946684800:
            return {}
        return {
            "expiry_epoch": epoch,
            "expires_at": datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
        }
    except (OverflowError, OSError, ValueError):
        return {}


def _normalized_expiry(value: Any, epoch: Any = None) -> str | None:
    try:
        numeric_epoch = int(epoch) if epoch not in {None, ""} else None
    except (TypeError, ValueError):
        numeric_epoch = None
    if numeric_epoch is not None:
        if numeric_epoch < 946684800:
            return None
        try:
            return datetime.fromtimestamp(numeric_epoch, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value or "").strip()
    if not text or text == "0":
        return None
    parsed: datetime | None = None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text[:19], pattern)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.year < 2000:
        return None
    return parsed.isoformat()


def _is_expired(value: str | None, epoch: int | None = None) -> bool:
    if epoch:
        return epoch <= int(datetime.now(timezone.utc).timestamp())
    if not value:
        return False
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:19], pattern) <= datetime.now()
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed <= datetime.now()
        return parsed <= datetime.now(timezone.utc)
    except ValueError:
        return False


def summarize_subscription_document(raw: bytes) -> dict[str, Any]:
    """Summarize a generic Mihomo subscription without applying Kato policy rules."""
    if not raw or len(raw) > MAX_SUBSCRIPTION_BYTES:
        raise SetupError("invalid_subscription", "Подписка пустая или слишком большая.")
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SetupError("invalid_subscription", "Ссылка вернула не Mihomo YAML.") from exc
    if not isinstance(document, Mapping):
        raise SetupError("invalid_subscription", "Ссылка вернула не Mihomo YAML.")
    proxies = document.get("proxies") or []
    providers = document.get("proxy-providers") or {}
    if not isinstance(proxies, list):
        proxies = []
    if not isinstance(providers, Mapping):
        providers = {}
    names = [str(item.get("name", "")) for item in proxies if isinstance(item, Mapping)]
    flags = {match for name in names for match in re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", name)}
    return {
        "servers": len(proxies),
        "providers": len(providers),
        "locations": len(flags),
    }


def fetch_subscription_summary(url: str, get: Callable[..., Any] = requests.get) -> dict[str, Any]:
    try:
        response = get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/yaml, application/yaml, */*"},
            timeout=(7, 20),
            allow_redirects=True,
        )
        final = urllib.parse.urlsplit(str(getattr(response, "url", url)))
        if int(response.status_code) != 200 or final.scheme.lower() != "https":
            raise ValueError("unexpected subscription response")
        summary = summarize_subscription_document(bytes(response.content))
        headers = getattr(response, "headers", {})
        if isinstance(headers, Mapping):
            summary.update(_subscription_userinfo(headers))
        return summary
    except SetupError:
        raise
    except Exception as exc:
        raise SetupError("subscription_unavailable", "Не удалось прочитать установленную подписку.") from exc


def _wifi_networks(raw: str) -> list[dict[str, Any]]:
    try:
        radios = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return []
    if not isinstance(radios, Mapping):
        return []
    networks: list[dict[str, Any]] = []
    for radio_name, radio in radios.items():
        if not isinstance(radio, Mapping):
            continue
        radio_config = radio.get("config") if isinstance(radio.get("config"), Mapping) else {}
        for interface in radio.get("interfaces", []) or []:
            if not isinstance(interface, Mapping):
                continue
            config = interface.get("config") if isinstance(interface.get("config"), Mapping) else {}
            if str(config.get("mode", "")) != "ap":
                continue
            network = config.get("network", [])
            if isinstance(network, str):
                network = [network]
            networks.append(
                {
                    "section": str(interface.get("section", "")),
                    "radio": str(radio_name),
                    "ssid": str(config.get("ssid", "Без имени")),
                    "encryption": str(config.get("encryption", "none")),
                    "band": str(radio_config.get("band", "unknown")),
                    "channel": str(radio_config.get("channel", "auto")),
                    "network": [str(item) for item in network] if isinstance(network, list) else [],
                    "up": bool(radio.get("up", False)),
                }
            )
    return networks


def _compatibility_checks(
    board: Mapping[str, Any],
    capacity: Mapping[str, str],
    internet: Mapping[str, str],
    *,
    installation_needed: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    release = board.get("release") if isinstance(board.get("release"), Mapping) else {}
    distribution = str(release.get("distribution") or release.get("description") or "").lower()
    firmware = str(release.get("version", ""))
    memory_kb = _integer(capacity, "memory_kb")
    overlay_kb = _integer(capacity, "overlay_free_kb")

    def check(
        code: str,
        title: str,
        ok: bool,
        value: str,
        recommendation: bool = False,
        scope: str = "always",
    ) -> dict[str, Any]:
        status = "pass" if ok else "recommend" if recommendation else "block"
        return {"code": code, "title": title, "status": status, "value": value, "scope": scope}

    is_openwrt = any(name in distribution for name in SUPPORTED_DISTRIBUTIONS)
    checks = [
        check("openwrt", "OpenWrt", is_openwrt and _version_pair(firmware) >= (24, 10), firmware or "не определена"),
        check("firewall", "Firewall4 / nftables", capacity.get("fw4") == capacity.get("nft") == "1", "готов" if capacity.get("fw4") == capacity.get("nft") == "1" else "не найден"),
        check("memory", "Оперативная память", memory_kb >= MIN_RAM_KB, f"{memory_kb // 1024} МБ"),
        check("internet", "Интернет с роутера", internet.get("dns") == internet.get("https") == "1", "доступен" if internet.get("dns") == internet.get("https") == "1" else "нет доступа"),
    ]
    install_checks = [
        check("package_manager", "Установка программ", capacity.get("opkg") == "1" or capacity.get("apk") == "1", "доступна" if capacity.get("opkg") == "1" or capacity.get("apk") == "1" else "не поддерживается", scope="install"),
        check("overlay", "Свободное место", overlay_kb >= MIN_INSTALL_OVERLAY_KB, f"{overlay_kb // 1024} МБ", scope="install"),
        check("overlay_writable", "Установка пакетов", capacity.get("overlay_writable") == "1", "доступна" if capacity.get("overlay_writable") == "1" else "раздел только для чтения", scope="install"),
    ]
    if memory_kb >= MIN_RAM_KB and memory_kb < RECOMMENDED_RAM_KB:
        checks.append(check("memory_recommended", "Рекомендуемая память", False, f"{memory_kb // 1024} МБ из 512 МБ", recommendation=True))
    visible_install_checks = [item for item in install_checks if item["code"] != "package_manager"]
    return checks + visible_install_checks if installation_needed else checks, checks + install_checks


def inspect_router(
    spec: ConnectionSpec,
    *,
    session_factory: Callable[[ConnectionSpec], RemoteSession] = RemoteSession,
    subscription_fetcher: Callable[[str], dict[str, Any]] = fetch_subscription_summary,
    package_fetcher: Callable[[str, str | None], dict[str, Any]] = fetch_latest_nikki_packages,
) -> dict[str, Any]:
    session = session_factory(spec)
    try:
        session.connect()
        board = json.loads(session.run("ubus call system board", label="control-board"))
        capacity = _key_values(
            session.run(
                "mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo); "
                "free=$(df -Pk /overlay 2>/dev/null | awk 'NR==2 {print $4}'); "
                "for c in uci fw4 nft opkg apk; do command -v \"$c\" >/dev/null 2>&1 && echo \"$c=1\" || echo \"$c=0\"; done; "
                "[ -x /www/cgi-bin/luci ] && echo luci=1 || echo luci=0; [ -x /etc/init.d/nikki ] && echo nikki=1 || echo nikki=0; "
                "if command -v opkg >/dev/null 2>&1; then opkg print-architecture 2>/dev/null | awk '$3>0 {a=$2} END {if(a) print \"package_arch=\" a}'; "
                "elif command -v apk >/dev/null 2>&1; then a=$(apk --print-arch 2>/dev/null); [ -n \"$a\" ] && echo \"package_arch=$a\"; fi; "
                "printf 'memory_kb=%s\\noverlay_free_kb=%s\\n' \"${mem:-0}\" \"${free:-0}\"; "
                "[ -w /overlay ] && echo overlay_writable=1 || echo overlay_writable=0",
                label="control-capacity",
                check=False,
            )
        )
        internet = _key_values(
            session.run(
                "nslookup openwrt.org >/dev/null 2>&1 && echo dns=1 || echo dns=0; "
                "if command -v curl >/dev/null 2>&1; then fetch='curl -fsSL --max-time 10'; "
                "elif command -v uclient-fetch >/dev/null 2>&1; then fetch='uclient-fetch -q -T 10 -O -'; "
                "elif command -v wget >/dev/null 2>&1; then fetch='wget -q -T 10 -O -'; else fetch=''; fi; "
                "[ -n \"$fetch\" ] && $fetch https://openwrt.org/ >/dev/null 2>&1 && echo https=1 || echo https=0; "
                "[ -n \"$fetch\" ] && $fetch https://nikkinikki.pages.dev/ >/dev/null 2>&1 && echo feed=1 || echo feed=0; "
                "[ $(date +%s 2>/dev/null || echo 0) -gt 1700000000 ] && echo clock=1 || echo clock=0",
                label="control-internet",
                timeout=35,
                check=False,
            )
        )
        public_ip_raw = session.run(
            "if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 10 -A 'KatoVPN-Router-Control/0.4' https://ipapi.co/json/; "
            "elif command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -T 10 -O - https://ipapi.co/json/; "
            "elif command -v wget >/dev/null 2>&1; then wget -q -T 10 -O - https://ipapi.co/json/; fi",
            label="control-public-ip",
            timeout=15,
            check=False,
        )
        packages: dict[str, dict[str, str]] = {}
        for package_name in (
            "nikki", "luci-app-nikki", "mihomo-meta", "mihomo-alpha", "mihomo",
            "adblock", "luci-app-adblock", "luci-i18n-adblock-ru",
        ):
            raw = session.run(
                f"(opkg status {package_name} 2>/dev/null; apk info -a {package_name} 2>/dev/null) || true",
                label=f"control-package-{package_name}",
                check=False,
            )
            packages.update(_package_blocks(raw))
        mihomo_runtime_raw = session.run(
            "if command -v mihomo >/dev/null 2>&1; then mihomo -v 2>/dev/null | head -n 1; "
            "elif [ -x /usr/bin/mihomo ]; then /usr/bin/mihomo -v 2>/dev/null | head -n 1; "
            "elif [ -x /usr/libexec/mihomo ]; then /usr/libexec/mihomo -v 2>/dev/null | head -n 1; "
            "else echo unknown; fi",
            label="control-mihomo-runtime",
            check=False,
        )
        nikki_state = _key_values(
            session.run(
                "printf 'status=%s\\nprofile=%s\\ntcp=%s\\nudp=%s\\n' \"$(/etc/init.d/nikki status 2>/dev/null || echo absent)\" "
                "\"$(uci -q get nikki.config.profile)\" \"$(uci -q get nikki.proxy.tcp_mode)\" \"$(uci -q get nikki.proxy.udp_mode)\"",
                label="control-nikki",
                check=False,
            )
        )
        subscription_raw = _key_values(
            session.run(
                "sid=$(uci -q get nikki.config.profile | sed -n 's/^subscription://p'); [ -n \"$sid\" ] || exit 0; "
                "printf 'id=%s\\nname=%s\\nurl=%s\\nuser_agent=%s\\nexpire=%s\\nsuccess=%s\\nupdate=%s\\n' \"$sid\" \"$(uci -q get nikki.$sid.name)\" "
                "\"$(uci -q get nikki.$sid.url)\" \"$(uci -q get nikki.$sid.user_agent)\" \"$(uci -q get nikki.$sid.expire)\" "
                "\"$(uci -q get nikki.$sid.success)\" \"$(uci -q get nikki.$sid.update)\"",
                label="control-subscription",
                check=False,
            )
        )
        lan_raw = _key_values(
            session.run(
                "printf 'ipaddr=%s\\nnetmask=%s\\nproto=%s\\n' \"$(uci -q get network.lan.ipaddr)\" "
                "\"$(uci -q get network.lan.netmask || echo 255.255.255.0)\" \"$(uci -q get network.lan.proto)\"; "
                "command -v start-stop-daemon >/dev/null 2>&1 && echo rollback=1 || echo rollback=0; "
                "printf 'uid=%s\\n' \"$(id -u 2>/dev/null || echo unknown)\"; "
                "command -v passwd >/dev/null 2>&1 && echo passwd=1 || echo passwd=0; "
                "[ -r /etc/shadow ] && [ -w /etc/shadow ] && echo shadow=1 || echo shadow=0; "
                "if uci show wireless 2>/dev/null | grep -Eq \"\\.encryption='?(sae|sae-mixed)\" || "
                "((opkg list-installed 2>/dev/null; apk info 2>/dev/null) | "
                "grep -Eq '^(wpad|hostapd)([[:space:]]|-(basic-)?(mbedtls|openssl|wolfssl)([[:space:]]|$))'); "
                "then echo wifi_sae=1; else echo wifi_sae=0; fi",
                label="control-lan",
                check=False,
            )
        )
        wifi_raw = session.run("wifi status 2>/dev/null || ubus call network.wireless status", label="control-wifi", check=False)
        backups_raw = session.run(
            "for d in /root/katovpn-nikki-backups/*; do [ -d \"$d\" ] || continue; id=${d##*/}; "
            "ts=$(stat -c %Y \"$d\" 2>/dev/null || echo 0); size=$(du -sk \"$d\" 2>/dev/null | awk '{print $1}'); "
            "enabled=$(cat \"$d/original-enabled\" 2>/dev/null || echo unknown); printf '%s\\t%s\\t%s\\t%s\\n' \"$id\" \"$ts\" \"${size:-0}\" \"$enabled\"; done | sort -r | head -20",
            label="control-backups",
            check=False,
        )

        release = board.get("release") if isinstance(board.get("release"), Mapping) else {}
        firmware = str(release.get("version", ""))
        mihomo_package_name = next(
            (name for name in ("mihomo-meta", "mihomo-alpha", "mihomo") if name in packages),
            None,
        )
        mihomo_package_version = (packages.get(mihomo_package_name or "") or {}).get("Version")
        mihomo_runtime_version = _runtime_version(mihomo_runtime_raw)
        mihomo_version = mihomo_runtime_version or mihomo_package_version
        arch = (
            (packages.get(mihomo_package_name or "") or {}).get("Architecture")
            or (packages.get("nikki") or {}).get("Architecture")
            or capacity.get("package_arch")
        )
        official = package_fetcher(firmware, arch)

        subscription: dict[str, Any] = {
            "configured": False, "staged": False, "state": "not_installed",
            "url": "", "expires_at": None, "source": "none", "reason": "not_installed",
        }
        url = subscription_raw.get("url", "")
        if url:
            cached_expiry = _normalized_expiry(subscription_raw.get("expire"))
            subscription.update(
                {
                    "configured": True,
                    "name": subscription_raw.get("name") or "KatoVPN",
                    "url": url,
                    "expires_at": cached_expiry,
                    "last_update": subscription_raw.get("update") or None,
                }
            )
            try:
                fresh = subscription_fetcher(url)
                fresh_expiry = _normalized_expiry(fresh.get("expires_at"), fresh.get("expiry_epoch"))
                subscription.update(fresh)
                subscription["expires_at"] = fresh_expiry
                subscription["status"] = "available"
                subscription["source"] = "live_link"
                subscription["state"] = "inactive" if _is_expired(subscription["expires_at"]) else "active"
                subscription["reason"] = "expired" if subscription["state"] == "inactive" else "verified"
            except SetupError:
                subscription["status"] = "unavailable"
                subscription["source"] = "nikki_cache"
                subscription["state"] = "inactive"
                subscription["reason"] = "link_unavailable"

        package_versions = official.get("packages") if isinstance(official.get("packages"), Mapping) else {}
        nikki_version = (packages.get("luci-app-nikki") or packages.get("nikki") or {}).get("Version")
        nikki_latest = package_versions.get("luci-app-nikki") or package_versions.get("nikki")
        mihomo_latest_package = mihomo_package_name if mihomo_package_name in {"mihomo-meta", "mihomo-alpha"} else "mihomo-meta"
        mihomo_latest = package_versions.get(mihomo_latest_package)
        nikki_update_available = bool(_semantic_version(nikki_latest) > _semantic_version(nikki_version))
        mihomo_update_available = bool(_semantic_version(mihomo_latest) > _semantic_version(mihomo_version))
        components = {
            "nikki": {
                "installed": capacity.get("nikki") == "1",
                "version": nikki_version,
                "package_version": (packages.get("nikki") or {}).get("Version"),
                "latest": nikki_latest,
                "managed": bool(packages.get("nikki") or packages.get("luci-app-nikki")),
                "update_available": nikki_update_available,
                "status": "update_available" if nikki_update_available else "current" if nikki_version else "missing",
            },
            "mihomo": {
                "installed": bool(mihomo_runtime_version),
                "version": mihomo_version,
                "runtime": mihomo_runtime_raw if mihomo_runtime_version else None,
                "managed": bool(mihomo_package_name),
                "package": mihomo_package_name,
                "package_version": mihomo_package_version,
                "latest": mihomo_latest,
                "update_available": mihomo_update_available,
                "status": (
                    "runtime_missing" if mihomo_package_name and not mihomo_runtime_version else
                    "update_available" if mihomo_update_available else
                    "current" if mihomo_runtime_version and mihomo_package_name else
                    "current_unmanaged" if mihomo_runtime_version else
                    "missing"
                ),
            },
            "adblock": {
                "installed": all(name in packages for name in ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru")),
                "partial": any(name in packages for name in ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru")),
                "version": (packages.get("adblock") or {}).get("Version"),
                "eligible": _integer(capacity, "memory_kb") >= ADBLOCK_CLASS_RAM_KB,
                "minimum_memory_mb": ADBLOCK_CLASS_RAM_KB // 1024,
                "packages": ["adblock", "luci-app-adblock", "luci-i18n-adblock-ru"],
                "status": "current" if all(name in packages for name in ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru")) else "partial" if any(name in packages for name in ("adblock", "luci-app-adblock", "luci-i18n-adblock-ru")) else "available",
            },
        }
        installation_needed = not components["nikki"]["installed"] or not components["mihomo"]["installed"]
        checks, install_checks = _compatibility_checks(
            board,
            capacity,
            internet,
            installation_needed=installation_needed,
        )
        blockers = [item for item in checks if item["status"] == "block"]
        install_blockers = [item for item in install_checks if item["status"] == "block"]
        return {
            "connected": True,
            "fingerprint": session.fingerprint,
            "router": {
                "hostname": str(board.get("hostname", "неизвестно")),
                "model": str(board.get("model", "неизвестно")),
                "board_name": str(board.get("board_name", "неизвестно")),
                "firmware": str(release.get("description") or firmware or "неизвестно"),
                "firmware_version": firmware,
                "kernel": str(board.get("kernel", "неизвестно")),
                "memory_mb": _integer(capacity, "memory_kb") // 1024,
                "package_manager": "opkg" if capacity.get("opkg") == "1" else "apk" if capacity.get("apk") == "1" else "unknown",
            },
            "internet": {
                "online": internet.get("dns") == internet.get("https") == "1",
                "dns": internet.get("dns") == "1",
                "https": internet.get("https") == "1",
                "nikki_feed": internet.get("feed") == "1",
                "clock_ok": internet.get("clock") == "1",
            },
            "public_ip": parse_public_ip_info(public_ip_raw),
            "compatibility": {
                "ready": not blockers,
                "install_ready": not install_blockers,
                "installation_needed": installation_needed,
                "checks": checks,
                "blockers": blockers,
            },
            "wifi": _wifi_networks(wifi_raw),
            "lan": {
                "ipaddr": lan_raw.get("ipaddr") or spec.host,
                "netmask": lan_raw.get("netmask") or "255.255.255.0",
                "proto": lan_raw.get("proto") or "unknown",
                "rollback_available": lan_raw.get("rollback") == "1",
                "recommended_country": "CN" if parse_public_ip_info(public_ip_raw).get("country_code") == "CN" else "RU",
            },
            "components": components,
            "nikki": {
                "status": nikki_state.get("status", "absent"),
                "profile": nikki_state.get("profile") or None,
                "mode": f"TCP {nikki_state.get('tcp', 'unknown')} + UDP {nikki_state.get('udp', 'unknown')}",
                "tun": nikki_state.get("tcp") == "tun" or nikki_state.get("udp") == "tun",
            },
            "subscription": subscription,
            "backups": _parse_backup_rows(backups_raw),
            "official_packages": {"status": official.get("status", "unavailable"), "branch": official.get("branch"), "versions": dict(package_versions)},
            "safety": {
                "hardware_mutations_validated": HARDWARE_MUTATIONS_VALIDATED,
                "install_enabled": HARDWARE_MUTATIONS_VALIDATED and not install_blockers,
                "wifi_changes_enabled": lan_raw.get("rollback") == "1" and lan_raw.get("wifi_sae") == "1" and bool(_wifi_networks(wifi_raw)),
                "wifi_create_enabled": lan_raw.get("rollback") == "1" and lan_raw.get("wifi_sae") == "1" and bool(_wifi_networks(wifi_raw)),
                "lan_changes_enabled": lan_raw.get("rollback") == "1" and lan_raw.get("proto") in {"static", ""},
                "password_change_enabled": (
                    lan_raw.get("rollback") == "1"
                    and lan_raw.get("uid") == "0"
                    and lan_raw.get("passwd") == "1"
                    and lan_raw.get("shadow") == "1"
                ),
                "backup_management_enabled": components["nikki"]["installed"],
                "adblock_install_enabled": components["adblock"]["eligible"] and not components["adblock"]["installed"] and internet.get("https") == "1",
                "log_export_enabled": components["nikki"]["installed"],
                "full_restore_enabled": HARDWARE_MUTATIONS_VALIDATED,
            },
        }
    except (json.JSONDecodeError, TypeError) as exc:
        raise SetupError("router_inspection", "Роутер вернул неполные сведения о системе.") from exc
    finally:
        session.close()


def _parse_backup_rows(raw: str) -> list[dict[str, Any]]:
    backups: list[dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{8}(?:-[0-9a-f]{4})?", parts[0]):
            continue
        backups.append({"id": parts[0], "size_kb": int(parts[2]) if parts[2].isdigit() else 0, "enabled": parts[3]})
    return backups


def build_install_plan(report: Mapping[str, Any], *, pc_packages_available: bool) -> dict[str, Any]:
    internet = report.get("internet") if isinstance(report.get("internet"), Mapping) else {}
    router = report.get("router") if isinstance(report.get("router"), Mapping) else {}
    compatibility = report.get("compatibility") if isinstance(report.get("compatibility"), Mapping) else {}
    manager = str(router.get("package_manager", "unknown"))
    if internet.get("nikki_feed"):
        method = "official_feed"
    elif pc_packages_available:
        method = "pc_upload"
    else:
        method = "unavailable"
    packages = [*NIKKI_DEPENDENCIES, *NIKKI_PACKAGES]
    if manager == "opkg" and method == "official_feed":
        commands = ["opkg update", "opkg install --noaction " + " ".join(packages), "opkg install " + " ".join(packages)]
    elif manager == "opkg" and method == "pc_upload":
        commands = ["opkg install --noaction /tmp/kato-nikki/*.ipk", "opkg install /tmp/kato-nikki/*.ipk"]
    elif manager == "apk" and method == "official_feed":
        commands = ["apk update", "apk add --simulate " + " ".join(packages), "apk add " + " ".join(packages)]
    elif manager == "apk" and method == "pc_upload":
        commands = ["apk add --simulate /tmp/kato-nikki/*.apk", "apk add /tmp/kato-nikki/*.apk"]
    else:
        commands = []
    return {
        "method": method,
        "packages": packages,
        "commands": commands,
        "dry_run_required": True,
        "backup_required": True,
        "hardware_validated": HARDWARE_MUTATIONS_VALIDATED,
        "enabled": bool(HARDWARE_MUTATIONS_VALIDATED and compatibility.get("install_ready") and method != "unavailable"),
    }
