"""Read-only assessment for automatic KatoVPN setup."""

from __future__ import annotations

import re
import shlex
from typing import Any, Protocol

from .core import PROFILE_NAME, USER_AGENT, validate_subscription_document


SETUP_MESSAGE = "Нужно настроить роутер для работы с KatoVPN"
EXTERNAL_SETTINGS_MESSAGE = (
    "На роутере обнаружены дополнительные сетевые настройки. "
    "Они могут влиять на работу KatoVPN."
)

_BOOLEAN_FLAGS = (
    "nikki_package",
    "luci_package",
    "mihomo_binary",
    "mihomo_valid",
    "nikki_init",
    "nikki_config",
    "enabled",
    "active_subscription",
    "managed_marker",
    "managed_name",
    "managed_user_agent",
    "tcp_redirect",
    "udp_tproxy",
    "ipv4_dns_hijack",
    "ipv6_proxy_disabled",
    "tun_dns_hijack_disabled",
    "tproxy_mark",
    "dns_contract",
    "proxy_contract",
    "policy_contract",
    "service_running",
    "mihomo_running",
    "nft_redirect",
    "nft_tproxy",
    "policy_routing",
    "dns_listener",
    "subscription_file",
    "runtime_file",
    "dnsmasq_forwarding",
    "dhcp_dns",
    "network_dns",
    "dnsmasq_override",
)
_COMPONENT_FLAGS = (
    "nikki_package",
    "luci_package",
    "mihomo_binary",
    "mihomo_valid",
    "nikki_init",
    "nikki_config",
)
_MANAGED_FLAGS = (
    "active_subscription",
    "managed_marker",
    "managed_name",
    "managed_user_agent",
)
_CONFIGURATION_FLAGS = (
    "active_subscription",
    "managed_user_agent",
    "tcp_redirect",
    "udp_tproxy",
    "ipv4_dns_hijack",
    "ipv6_proxy_disabled",
    "tun_dns_hijack_disabled",
    "tproxy_mark",
    "dns_contract",
    "proxy_contract",
    "policy_contract",
    "subscription_file",
)
_RUNTIME_FLAGS = (
    "enabled",
    "service_running",
    "mihomo_running",
    "nft_redirect",
    "nft_tproxy",
    "policy_routing",
    "dns_listener",
    "runtime_file",
)
_EXTERNAL_SERVICES = (
    "adguardhome",
    "smartdns",
    "mosdns",
    "dnscrypt-proxy",
    "https-dns-proxy",
    "openclash",
    "passwall",
    "passwall2",
    "shadowsocksr",
    "homeproxy",
    "dae",
    "sing-box",
    "xray",
    "v2ray",
)

# Supplementary diagnostic flags do not change the core evidence contract.
_DNS_DETAIL_FLAGS = ("dnsmasq_noresolv", "dnsmasq_dns_redirect", "dnsmasq_nonstandard_port")


class SetupInspectionSession(Protocol):
    def run(self, command: str, *, label: str, timeout: int = 20, check: bool = True) -> str: ...
    def read_file(self, remote_path: str, *, max_bytes: int = 5 * 1024 * 1024) -> bytes: ...


def _flag_command(key: str, condition: str) -> str:
    return f"if {condition}; then printf '{key}=1\\n'; else printf '{key}=0\\n'; fi"


def _probe_command() -> str:
    services = " ".join(shlex.quote(item) for item in _EXTERNAL_SERVICES)
    conditions = {
        "nikki_package": "pkg_installed nikki",
        "luci_package": "pkg_installed luci-app-nikki",
        "mihomo_binary": "command -v mihomo >/dev/null 2>&1 || test -x /usr/libexec/mihomo || test -x /usr/bin/mihomo",
        "mihomo_valid": (
            "if command -v mihomo >/dev/null 2>&1; then mihomo -v >/dev/null 2>&1; "
            "elif test -x /usr/libexec/mihomo; then /usr/libexec/mihomo -v >/dev/null 2>&1; "
            "elif test -x /usr/bin/mihomo; then /usr/bin/mihomo -v >/dev/null 2>&1; else false; fi"
        ),
        "nikki_init": "test -x /etc/init.d/nikki",
        "nikki_config": "uci -q show nikki >/dev/null 2>&1",
        "enabled": "test \"$(uci -q get nikki.config.enabled 2>/dev/null)\" = 1",
        "active_subscription": "test -n \"$sid\" && uci -q get nikki.$sid >/dev/null 2>&1",
        "managed_marker": "test -n \"$sid\" && test \"$(uci -q get nikki.$sid.kato_managed 2>/dev/null)\" = 1",
        "managed_name": "test -n \"$sid\" && test \"$(uci -q get nikki.$sid.name 2>/dev/null)\" = \"$expected_name\"",
        "managed_user_agent": "test -n \"$sid\" && test \"$(uci -q get nikki.$sid.user_agent 2>/dev/null)\" = \"$expected_ua\"",
        "tcp_redirect": "test \"$(uci -q get nikki.proxy.tcp_mode 2>/dev/null)\" = redirect",
        "udp_tproxy": "test \"$(uci -q get nikki.proxy.udp_mode 2>/dev/null)\" = tproxy",
        "ipv4_dns_hijack": "test \"$(uci -q get nikki.proxy.ipv4_dns_hijack 2>/dev/null)\" = 1",
        "ipv6_proxy_disabled": "test \"$(uci -q get nikki.proxy.ipv6_proxy 2>/dev/null)\" = 0",
        "tun_dns_hijack_disabled": "test \"$(uci -q get nikki.mixin.tun_dns_hijack 2>/dev/null)\" = 0",
        "tproxy_mark": "test \"$(uci -q get nikki.routing.tproxy_fw_mark 2>/dev/null)\" = 0x80",
        "dns_contract": (
            "test \"$(uci -q get nikki.mixin.dns_enabled 2>/dev/null)\" = 1 && "
            "test \"$(uci -q get nikki.mixin.dns_listen 2>/dev/null)\" = '[::]:1053' && "
            "test \"$(uci -q get nikki.mixin.dns_mode 2>/dev/null)\" = fake-ip && "
            "test \"$(uci -q get nikki.proxy.ipv4_dns_hijack 2>/dev/null)\" = 1 && "
            "test \"$(uci -q get nikki.proxy.ipv6_dns_hijack 2>/dev/null)\" = 0 && "
            "test \"$(uci -q get nikki.mixin.tun_dns_hijack 2>/dev/null)\" = 0"
        ),
        "proxy_contract": (
            "test \"$(uci -q get nikki.proxy.tcp_mode 2>/dev/null)\" = redirect && "
            "test \"$(uci -q get nikki.proxy.udp_mode 2>/dev/null)\" = tproxy && "
            "test \"$(uci -q get nikki.proxy.ipv4_proxy 2>/dev/null)\" = 1 && "
            "test \"$(uci -q get nikki.proxy.ipv6_proxy 2>/dev/null)\" = 0 && "
            "test \"$(uci -q get nikki.proxy.router_proxy 2>/dev/null)\" = 1 && "
            "test \"$(uci -q get nikki.proxy.lan_proxy 2>/dev/null)\" = 1 && "
            "test \"$(uci -q get nikki.proxy.lan_inbound_interface 2>/dev/null)\" = lan && "
            "test \"$(uci -q get nikki.mixin.redir_port 2>/dev/null)\" = 7891 && "
            "test \"$(uci -q get nikki.mixin.tproxy_port 2>/dev/null)\" = 7892"
        ),
        "policy_contract": (
            "test \"$(uci -q get nikki.mixin.mode 2>/dev/null)\" = rule && "
            "test \"$(uci -q get nikki.mixin.rule 2>/dev/null)\" = 0 && "
            "test \"$(uci -q get nikki.mixin.rule_provider 2>/dev/null)\" = 0 && "
            "test \"$(uci -q get nikki.mixin.mixin_file_content 2>/dev/null)\" = 0 && "
            "test \"$(uci -q get nikki.routing.tproxy_fw_mark 2>/dev/null)\" = 0x80 && "
            "test \"$(uci -q get nikki.routing.tproxy_fw_mask 2>/dev/null)\" = 0xFF && "
            "test \"$(uci -q get nikki.routing.tproxy_rule_pref 2>/dev/null)\" = 1024 && "
            "test \"$(uci -q get nikki.routing.tproxy_route_table 2>/dev/null)\" = 80"
        ),
        "service_running": "/etc/init.d/nikki status >/dev/null 2>&1",
        "mihomo_running": "pidof mihomo >/dev/null 2>&1",
        "nft_redirect": "nft list table inet nikki 2>/dev/null | grep -q 'chain lan_redirect'",
        "nft_tproxy": "nft list table inet nikki 2>/dev/null | grep -q 'chain lan_tproxy'",
        "policy_routing": "ip -4 rule show 2>/dev/null | grep -q 'fwmark 0x80/0xff lookup 80'",
        "dns_listener": (
            "(command -v ss >/dev/null 2>&1 && ss -H -lnup 2>/dev/null | grep -Eq '(:|\\])1053([[:space:]]|$)') || "
            "(command -v netstat >/dev/null 2>&1 && netstat -lnu 2>/dev/null | grep -Eq '(:|\\])1053[[:space:]]') || "
            "awk '$2 ~ /:041D$/ { found=1 } END { exit !found }' /proc/net/udp /proc/net/udp6 2>/dev/null"
        ),
        "subscription_file": "test -n \"$sid\" && test -s /etc/nikki/subscriptions/$sid.yaml",
        "runtime_file": "test -s /etc/nikki/run/config.yaml",
        "dnsmasq_forwarding": "uci -q show dhcp 2>/dev/null | grep -Eq \"^dhcp\\..*\\.server='[^']\"",
        "dhcp_dns": "uci -q show dhcp 2>/dev/null | grep -Eq \"^dhcp\\..*(\\.dns='[^']|\\.dhcp_option=.*6,)\"",
        "network_dns": "uci -q show network 2>/dev/null | grep -Eq \"^network\\..*(\\.dns='[^']|\\.peerdns='0')\"",
        "dnsmasq_override": (
            "test \"$(uci -q get dhcp.@dnsmasq[0].noresolv 2>/dev/null)\" = 1 || "
            "test \"$(uci -q get dhcp.@dnsmasq[0].dns_redirect 2>/dev/null)\" = 1 || "
            "{ dnsmasq_port=$(uci -q get dhcp.@dnsmasq[0].port 2>/dev/null); "
            "test -n \"$dnsmasq_port\" && test \"$dnsmasq_port\" != 53; }"
        ),
    }
    conditions.update({
        "dnsmasq_noresolv": "test \"$(uci -q get dhcp.@dnsmasq[0].noresolv 2>/dev/null)\" = 1",
        "dnsmasq_dns_redirect": "test \"$(uci -q get dhcp.@dnsmasq[0].dns_redirect 2>/dev/null)\" = 1",
        "dnsmasq_nonstandard_port": (
            "{ dnsmasq_port=$(uci -q get dhcp.@dnsmasq[0].port 2>/dev/null); "
            "test -n \"$dnsmasq_port\" && test \"$dnsmasq_port\" != 53; }"
        ),
    })
    prefix = (
        "pkg_installed() { "
        "opkg status \"$1\" 2>/dev/null | grep -q '^Status: .* installed' || "
        "apk info -e \"$1\" >/dev/null 2>&1; }; "
        "printf 'evidence_version=1\\n'; "
        f"expected_name={shlex.quote(PROFILE_NAME)}; expected_ua={shlex.quote(USER_AGENT)}; "
        "profile=$(uci -q get nikki.config.profile 2>/dev/null || true); sid=''; "
        "case \"$profile\" in subscription:*) sid=${profile#subscription:};; esac; "
        "case \"$sid\" in ''|*[!A-Za-z0-9_-]*) sid='';; esac; "
    )
    flags = "; ".join(_flag_command(key, conditions[key]) for key in (*_BOOLEAN_FLAGS, *_DNS_DETAIL_FLAGS))
    suffix = (
        "; external=''; for service in " + services + "; do "
        "if test -x /etc/init.d/$service && /etc/init.d/$service status >/dev/null 2>&1; then "
        "external=\"${external}${external:+,}$service\"; fi; done; "
        "printf 'external_services=%s\\n' \"$external\""
    )
    return prefix + flags + suffix


def _parse_probe(raw: str) -> tuple[dict[str, bool], list[str]] | None:
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if values.get("evidence_version") != "1" or any(values.get(key) not in {"0", "1"} for key in _BOOLEAN_FLAGS):
        return None
    external = [item for item in values.get("external_services", "").split(",") if item]
    if any(item not in _EXTERNAL_SERVICES for item in external):
        return None
    if any(key in values and values[key] not in {"0", "1"} for key in _DNS_DETAIL_FLAGS):
        return None
    return ({key: values.get(key) == "1" for key in (*_BOOLEAN_FLAGS, *_DNS_DETAIL_FLAGS)}, sorted(set(external)))


def inspect_router_setup(session: SetupInspectionSession) -> dict[str, Any]:
    """Classify setup readiness using bounded flags without reading secret values."""
    try:
        raw = session.run(
            _probe_command(),
            label="состояние автоматической настройки",
            timeout=35,
            check=False,
        )
    except Exception:
        raw = ""
    parsed = _parse_probe(raw)
    if parsed is None:
        return {
            "state": "unknown",
            "action": "blocked",
            "message": SETUP_MESSAGE,
            "warnings": [],
            "details": {"evidence_complete": False},
        }

    flags, external_services = parsed
    runtime_document_valid = False
    if flags["runtime_file"]:
        try:
            validate_subscription_document(
                session.read_file("/etc/nikki/run/config.yaml", max_bytes=5 * 1024 * 1024)
            )
            runtime_document_valid = True
        except Exception:
            runtime_document_valid = False
    component_count = sum(flags[key] for key in _COMPONENT_FLAGS)
    components = "absent" if component_count == 0 else "complete" if component_count == len(_COMPONENT_FLAGS) else "partial"
    managed = all(flags[key] for key in _MANAGED_FLAGS)
    # Ownership metadata is not evidence of compatibility (or incompatibility).
    configuration_mismatches = [key for key in _CONFIGURATION_FLAGS if not flags[key]]
    configuration_verified = not configuration_mismatches
    runtime_mismatches = [key for key in _RUNTIME_FLAGS if not flags[key]]
    if not runtime_document_valid:
        runtime_mismatches.append("runtime_document_valid")
    runtime_checks_passed = not runtime_mismatches
    runtime_verified = configuration_verified and runtime_checks_passed

    warning_reasons: list[str] = []
    if external_services:
        warning_reasons.append("active_dns_or_proxy_service")
    if flags["dhcp_dns"]:
        warning_reasons.append("custom_dhcp_dns")
    if flags["dnsmasq_forwarding"]:
        warning_reasons.append("custom_dnsmasq_forwarding")
    if flags["dnsmasq_override"]:
        warning_reasons.append("custom_dnsmasq_options")
    if flags["network_dns"]:
        warning_reasons.append("custom_network_dns")
    warnings = (
        [{"code": "external_network_settings", "message": EXTERNAL_SETTINGS_MESSAGE}]
        if warning_reasons
        else []
    )

    if components == "absent":
        state, action = "needs_install", "install"
    elif components == "partial":
        state, action = "needs_repair", "install"
    elif runtime_verified:
        state, action = "ready", "refresh"
    elif managed:
        state, action = "needs_repair", "configure"
    else:
        state, action = "needs_configuration", "configure"

    return {
        "state": state,
        "action": action,
        "message": "Роутер настроен для работы с KatoVPN." if state == "ready" else SETUP_MESSAGE,
        "warnings": warnings,
        "details": {
            "evidence_complete": True,
            "components": components,
            "managed": managed,
            "configuration_verified": configuration_verified,
            "configuration_mismatches": configuration_mismatches,
            "runtime_verified": runtime_verified,
            "runtime_checks_passed": runtime_checks_passed,
            "runtime_mismatches": runtime_mismatches,
            "runtime_document_valid": runtime_document_valid,
            "external_services": external_services,
            "warning_reasons": warning_reasons,
            "dnsmasq_options": [key for key in _DNS_DETAIL_FLAGS if flags[key]],
        },
    }


__all__ = ["EXTERNAL_SETTINGS_MESSAGE", "SETUP_MESSAGE", "inspect_router_setup"]
