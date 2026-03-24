from __future__ import annotations

import os
import secrets
import socket
import string
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from .constants import (
    PROXY_HOST,
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    SINGBOX_CLASH_API_PORT,
    SS_PROTECT_PORT_START,
    SS_PROTECT_PORT_END,
    XRAY_STATS_API_PORT,
)
from .models import AppSettings, Node, RoutingSettings
from .process_presets import PROCESS_PRESETS_BY_ID
from .service_presets import SERVICE_PRESETS_BY_ID

_XRAY_SOCKS_PORT = 11808
_SS_PROTECT_METHOD = "chacha20-ietf-poly1305"

_PROTECTED_PROCESSES = {"xray.exe", "sing-box.exe", "tun2socks.exe"}


def _find_free_port(start: int = SS_PROTECT_PORT_START, end: int = SS_PROTECT_PORT_END) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {start}-{end}")


def _generate_ss_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@dataclass
class TunConfigBundle:
    singbox_config: dict[str, Any]
    xray_config: dict[str, Any] | None  # None for native mode
    is_hybrid: bool
    protect_port: int = 0
    protect_password: str = ""


def needs_xray_hybrid(node: Node) -> bool:
    """Return True if node uses a transport that sing-box cannot handle natively."""
    stream = dict(node.outbound.get("streamSettings") or {})
    network = str(stream.get("network") or "tcp").lower()
    return network == "xhttp"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_singbox_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
    protect_port: int = 0,
    protect_password: str = "",
) -> TunConfigBundle:
    if needs_xray_hybrid(node):
        return _build_hybrid_config(node, routing, settings, protect_port, protect_password)
    return _build_native_config(node, routing, settings)


def build_xray_hybrid_config(
    node: Node, routing: RoutingSettings, settings: AppSettings,
    protect_port: int, protect_password: str,
) -> dict[str, Any]:
    """Public wrapper for hot-swap: rebuild only xray config with existing protect params."""
    return _build_xray_hybrid_config(node, routing, settings, protect_port, protect_password)


# ---------------------------------------------------------------------------
# Protected process rules
# ---------------------------------------------------------------------------

def _append_protected_process_rules(rules: list[dict[str, Any]], settings: AppSettings) -> None:
    protected = list(_PROTECTED_PROCESSES)
    if settings.xray_path:
        protected.append(Path(settings.xray_path).name)
    if settings.singbox_path:
        protected.append(Path(settings.singbox_path).name)
    seen: set[str] = set()
    deduped: list[str] = []
    for p in protected:
        low = p.lower()
        if low not in seen:
            seen.add(low)
            deduped.append(low)
    rules.append({"process_name": deduped, "outbound": "direct"})


# ---------------------------------------------------------------------------
# Hybrid: sing-box TUN + xray SOCKS (dialerProxy architecture)
# ---------------------------------------------------------------------------

def _build_hybrid_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
    protect_port: int = 0,
    protect_password: str = "",
) -> TunConfigBundle:
    if not protect_port:
        protect_port = _find_free_port()
    if not protect_password:
        protect_password = _generate_ss_password()

    singbox_cfg = _build_hybrid_singbox_config(node, routing, settings, protect_port, protect_password)
    xray_cfg = _build_xray_hybrid_config(node, routing, settings, protect_port, protect_password)

    return TunConfigBundle(
        singbox_config=singbox_cfg,
        xray_config=xray_cfg,
        is_hybrid=True,
        protect_port=protect_port,
        protect_password=protect_password,
    )


def _build_hybrid_singbox_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
    protect_port: int,
    protect_password: str,
) -> dict[str, Any]:
    """sing-box config for hybrid mode: TUN + SS protect inbound + relay to xray SOCKS."""
    relay_outbound: dict[str, Any] = {
        "type": "socks",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": _XRAY_SOCKS_PORT,
        "inet4_bind_address": "127.0.0.1",
    }
    direct_out: dict[str, Any] = {"type": "direct", "tag": "direct", "domain_resolver": "bootstrap-dns"}
    block_out: dict[str, Any] = {"type": "block", "tag": "block"}

    route_rules: list[dict[str, Any]] = []

    route_rules.append({"action": "sniff"})
    route_rules.append({"protocol": "dns", "action": "hijack-dns"})

    # Protected processes bypass TUN
    _append_protected_process_rules(route_rules, settings)

    # SS protect inbound → direct (loopback traffic from xray dialerProxy)
    route_rules.append({"inbound": ["tun-protect"], "outbound": "direct"})

    # Bypass LAN
    if routing.bypass_lan:
        route_rules.append({"ip_is_private": True, "outbound": "direct"})

    # Service routes
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if preset:
            _append_singbox_rules(route_rules, list(preset.domains), action)

    # Domain rules
    _append_singbox_rules(route_rules, routing.direct_domains, "direct")
    _append_singbox_rules(route_rules, routing.block_domains, "block")
    _append_singbox_rules(route_rules, routing.proxy_domains, "proxy")

    # Process rules
    _append_process_rules(route_rules, routing)

    # Default outbound for TUN
    if routing.tun_default_outbound == "direct":
        final_outbound = "direct"
    else:
        final_outbound = "proxy"

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": f"xftun{os.getpid() % 10000}",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": False,
                "stack": "mixed",
            },
            {
                "type": "shadowsocks",
                "tag": "tun-protect",
                "listen": "127.0.0.1",
                "listen_port": protect_port,
                "method": _SS_PROTECT_METHOD,
                "password": protect_password,
            },
        ],
        "outbounds": [relay_outbound, direct_out, block_out],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "proxy-dns",
            "final": final_outbound,
            "rules": route_rules,
        },
        "dns": {
            "servers": [
                {"tag": "bootstrap-dns", "type": routing.dns_bootstrap_type, "server": routing.dns_bootstrap_server},
                {"tag": "proxy-dns", "type": routing.dns_proxy_type, "server": routing.dns_proxy_server, "detour": "proxy"},
            ],
            "final": "proxy-dns",
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{SINGBOX_CLASH_API_PORT}",
            },
        },
    }


def _build_xray_hybrid_config(
    node: Node, routing: RoutingSettings, settings: AppSettings,
    protect_port: int, protect_password: str,
) -> dict[str, Any]:
    """Build xray config for hybrid mode: SOCKS inbound + dialerProxy to SS protect."""
    from .config_builder import build_xray_config
    cfg = build_xray_config(node, routing, settings)

    # Replace inbounds: internal SOCKS (for sing-box relay) + user proxy ports + API
    socks_port = settings.socks_port or 10808
    http_port = settings.http_port or 8080
    cfg["inbounds"] = [
        {
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": _XRAY_SOCKS_PORT,
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        },
        {
            "tag": "socks-user",
            "protocol": "socks",
            "listen": PROXY_HOST,
            "port": socks_port,
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        },
        {
            "tag": "http-user",
            "protocol": "http",
            "listen": PROXY_HOST,
            "port": http_port,
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        },
        {
            "tag": "api",
            "listen": PROXY_HOST,
            "port": XRAY_STATS_API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": PROXY_HOST},
        },
    ]

    # Add dialerProxy to the proxy outbound
    for ob in cfg.get("outbounds", []):
        if ob.get("tag") == "proxy":
            ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "tun-protect-out"
            break

    # Add SS protect outbound
    ss_protect = {
        "tag": "tun-protect-out",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": "127.0.0.1",
                "port": protect_port,
                "method": _SS_PROTECT_METHOD,
                "password": protect_password,
            }]
        },
    }
    cfg["outbounds"].append(ss_protect)

    return cfg


# ---------------------------------------------------------------------------
# Native: sing-box handles everything (non-xhttp transports)
# ---------------------------------------------------------------------------

def _build_native_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
) -> TunConfigBundle:
    proxy_outbound = _convert_outbound(deepcopy(node.outbound))
    proxy_outbound["tag"] = "proxy"
    proxy_outbound["domain_resolver"] = "proxy-dns"

    direct_out: dict[str, Any] = {"type": "direct", "tag": "direct", "domain_resolver": "bootstrap-dns"}
    block_out: dict[str, Any] = {"type": "block", "tag": "block"}

    route_rules = _build_route_rules(routing, node, settings)

    final_outbound = "direct" if routing.tun_default_outbound == "direct" else "proxy"

    singbox_cfg: dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": f"xftun{os.getpid() % 10000}",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": False,
                "stack": "mixed",
            },
        ],
        "outbounds": [proxy_outbound, direct_out, block_out],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "proxy-dns",
            "final": final_outbound,
            "rules": route_rules,
        },
        "dns": {
            "servers": [
                {"tag": "bootstrap-dns", "type": routing.dns_bootstrap_type, "server": routing.dns_bootstrap_server},
                {"tag": "proxy-dns", "type": routing.dns_proxy_type, "server": routing.dns_proxy_server, "detour": "proxy"},
            ],
            "final": "proxy-dns",
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{SINGBOX_CLASH_API_PORT}",
            },
        },
    }

    return TunConfigBundle(singbox_config=singbox_cfg, xray_config=None, is_hybrid=False)


# ---------------------------------------------------------------------------
# Outbound conversion (xray -> sing-box format)
# ---------------------------------------------------------------------------

def _convert_outbound(xray_ob: dict[str, Any]) -> dict[str, Any]:
    protocol = str(xray_ob.get("protocol") or "").lower()
    xray_settings = dict(xray_ob.get("settings") or {})
    stream = dict(xray_ob.get("streamSettings") or {})

    sb: dict[str, Any] = {"type": protocol}

    if protocol in ("vless", "vmess"):
        vnext = (xray_settings.get("vnext") or [{}])[0]
        sb["server"] = str(vnext.get("address") or "")
        sb["server_port"] = int(vnext.get("port") or 0)
        users = (vnext.get("users") or [{}])[0]
        sb["uuid"] = str(users.get("id") or "")
        if protocol == "vless":
            flow = str(users.get("flow") or "")
            if flow:
                sb["flow"] = flow
        if protocol == "vmess":
            sb["alter_id"] = int(users.get("alterId") or 0)
            sb["security"] = str(users.get("security") or "auto")

    elif protocol == "trojan":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["password"] = str(servers.get("password") or "")

    elif protocol == "shadowsocks":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["method"] = str(servers.get("method") or "")
        sb["password"] = str(servers.get("password") or "")

    elif protocol in ("socks", "http"):
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        user_list = servers.get("users") or []
        if user_list:
            sb["username"] = str(user_list[0].get("user") or "")
            sb["password"] = str(user_list[0].get("pass") or "")

    _apply_tls(sb, stream)
    _apply_transport(sb, stream)

    return sb


def _apply_tls(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    security = str(stream.get("security") or "").lower()
    if security not in ("tls", "reality"):
        return

    tls: dict[str, Any] = {"enabled": True}

    if security == "reality":
        reality_settings = dict(stream.get("realitySettings") or {})
        tls["server_name"] = str(reality_settings.get("serverName") or "")
        fp = str(reality_settings.get("fingerprint") or "")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        pub = str(reality_settings.get("publicKey") or "")
        sid = str(reality_settings.get("shortId") or "")
        tls["reality"] = {"enabled": True, "public_key": pub, "short_id": sid}
    else:
        tls_settings = dict(stream.get("tlsSettings") or {})
        sni = str(tls_settings.get("serverName") or "")
        if sni:
            tls["server_name"] = sni
        alpn = tls_settings.get("alpn")
        if alpn:
            tls["alpn"] = list(alpn)
        fp = str(tls_settings.get("fingerprint") or "")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        insecure = tls_settings.get("allowInsecure", False)
        if insecure:
            tls["insecure"] = True

    sb["tls"] = tls


def _apply_transport(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    network = str(stream.get("network") or "tcp").lower()

    if network == "tcp":
        return

    if network == "ws":
        ws_settings = dict(stream.get("wsSettings") or {})
        transport: dict[str, Any] = {"type": "ws"}
        path = str(ws_settings.get("path") or "")
        if path:
            transport["path"] = path
        headers = dict(ws_settings.get("headers") or {})
        if headers:
            transport["headers"] = headers
        sb["transport"] = transport

    elif network in ("http", "h2"):
        h2_settings = dict(stream.get("httpSettings") or stream.get("h2Settings") or {})
        transport = {"type": "http"}
        host = h2_settings.get("host")
        if host:
            transport["host"] = list(host) if isinstance(host, list) else [str(host)]
        path = str(h2_settings.get("path") or "")
        if path:
            transport["path"] = path
        sb["transport"] = transport

    elif network == "grpc":
        grpc_settings = dict(stream.get("grpcSettings") or {})
        transport = {"type": "grpc"}
        sn = str(grpc_settings.get("serviceName") or "")
        if sn:
            transport["service_name"] = sn
        sb["transport"] = transport

    elif network == "xhttp":
        sb["_unsupported_transport"] = "xhttp"


# ---------------------------------------------------------------------------
# Routing rules (for native mode)
# ---------------------------------------------------------------------------

def _build_route_rules(routing: RoutingSettings, node: Node, settings: AppSettings) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    rules.append({"action": "sniff"})
    rules.append({"protocol": "dns", "action": "hijack-dns"})

    # Protected processes bypass TUN
    _append_protected_process_rules(rules, settings)

    bypass_ips: list[str] = []
    if node.server:
        bypass_ips.append(f"{node.server}/32")
    if bypass_ips:
        rules.append({"ip_cidr": bypass_ips, "outbound": "direct"})

    if routing.bypass_lan:
        rules.append({"ip_is_private": True, "outbound": "direct"})

    # Service routes
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if preset:
            _append_singbox_rules(rules, list(preset.domains), action)

    _append_singbox_rules(rules, routing.direct_domains, "direct")
    _append_singbox_rules(rules, routing.block_domains, "block")
    _append_singbox_rules(rules, routing.proxy_domains, "proxy")

    _append_process_rules(rules, routing)

    return rules


def _append_process_rules(rules: list[dict[str, Any]], routing: RoutingSettings) -> None:
    """Group manual process rules + process presets by action and append."""
    proc_by_action: dict[str, list[str]] = {}

    # Process presets (quick-add groups)
    for preset_id, action in routing.process_preset_routes.items():
        preset = PROCESS_PRESETS_BY_ID.get(preset_id)
        if preset and action in ("direct", "proxy", "block"):
            for exe in preset.processes:
                proc_by_action.setdefault(action, []).append(exe)

    # Manual process rules (user-added exe files)
    for pr in routing.process_rules:
        name = pr.get("process", "").strip()
        action = pr.get("action", "proxy")
        if name and action in ("direct", "proxy", "block"):
            proc_by_action.setdefault(action, []).append(name)

    for action, names in proc_by_action.items():
        # Deduplicate (case-insensitive)
        seen: set[str] = set()
        unique: list[str] = []
        for n in names:
            low = n.lower()
            if low not in seen:
                seen.add(low)
                unique.append(n)
        rules.append({"process_name": unique, "outbound": action})


def _append_singbox_rules(
    rules: list[dict[str, Any]],
    items: list[str],
    outbound: str,
) -> None:
    domain_suffix: list[str] = []
    domain_full: list[str] = []
    domain_keyword: list[str] = []
    ip_cidr: list[str] = []

    for raw in items:
        value = raw.strip()
        if not value:
            continue

        if value.startswith("domain:"):
            domain_suffix.append(value[len("domain:"):])
        elif value.startswith("full:"):
            domain_full.append(value[len("full:"):])
        elif value.startswith("keyword:"):
            domain_keyword.append(value[len("keyword:"):])
        elif value.startswith("geosite:") or value.startswith("geoip:"):
            continue
        else:
            try:
                ip_network(value, strict=False)
                ip_cidr.append(value)
                continue
            except ValueError:
                pass
            domain_suffix.append(value)

    if domain_suffix:
        rules.append({"domain_suffix": domain_suffix, "outbound": outbound})
    if domain_full:
        rules.append({"domain": domain_full, "outbound": outbound})
    if domain_keyword:
        rules.append({"domain_keyword": domain_keyword, "outbound": outbound})
    if ip_cidr:
        rules.append({"ip_cidr": ip_cidr, "outbound": outbound})
