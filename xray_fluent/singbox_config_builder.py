from __future__ import annotations

import os
from copy import deepcopy
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from .constants import (
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    SINGBOX_CLASH_API_PORT,
)
from .models import AppSettings, Node, RoutingSettings


_XRAY_SOCKS_PORT = 11808


def needs_xray_hybrid(node: Node) -> bool:
    """Return True if node uses a transport that sing-box cannot handle natively."""
    stream = dict(node.outbound.get("streamSettings") or {})
    network = str(stream.get("network") or "tcp").lower()
    return network == "xhttp"


def build_singbox_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
) -> dict[str, Any]:
    if needs_xray_hybrid(node):
        return _build_hybrid_config(node, routing, settings)
    return _build_native_config(node, routing, settings)


def build_xray_socks_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
) -> dict[str, Any]:
    """Build a minimal xray config that exposes SOCKS on localhost for sing-box TUN."""
    from .config_builder import build_xray_config
    cfg = build_xray_config(node, routing, settings)
    # Replace inbounds with a single localhost SOCKS
    cfg["inbounds"] = [
        {
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": _XRAY_SOCKS_PORT,
            "settings": {"auth": "noauth", "udp": True},
        }
    ]
    return cfg


def _build_hybrid_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
) -> dict[str, Any]:
    """sing-box TUN config that routes traffic through xray SOCKS proxy."""
    proxy_outbound: dict[str, Any] = {
        "type": "socks",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": _XRAY_SOCKS_PORT,
        "domain_resolver": "proxy-dns",
    }

    direct_out: dict[str, Any] = {"type": "direct", "tag": "direct", "domain_resolver": "proxy-dns"}
    block_out: dict[str, Any] = {"type": "block", "tag": "block"}

    outbounds = [proxy_outbound, direct_out, block_out]

    # In hybrid mode sing-box is just a TUN wrapper — all traffic goes to
    # xray SOCKS which handles DNS, routing, and the actual proxy protocol.
    # Keep rules minimal: bypass xray + loopback + LAN, send everything else to proxy.
    route_rules: list[dict[str, Any]] = []

    # CRITICAL: bypass xray.exe to prevent routing loop.
    # Without this, xray's "direct" outbound traffic gets captured by TUN
    # and sent back to xray SOCKS, creating an infinite loop.
    xray_bin = Path(settings.xray_path).name if settings.xray_path else "xray.exe"
    route_rules.append({"process_name": [xray_bin], "outbound": "direct"})

    bypass_ips = ["127.0.0.0/8"]
    if node.server:
        bypass_ips.append(f"{node.server}/32")
    route_rules.append({"ip_cidr": bypass_ips, "outbound": "direct"})
    if routing.bypass_lan:
        route_rules.append({"ip_is_private": True, "outbound": "direct"})

    # Process-based routing (sing-box detects originating process via OS APIs)
    _append_process_rules(route_rules, routing)

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": f"xftun{os.getpid() % 10000}",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniff": True,
                "sniff_override_destination": True,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "proxy-dns",
            "rules": route_rules,
        },
        "dns": {
            "servers": [
                {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1", "detour": "proxy"},
            ],
            "final": "proxy-dns",
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{SINGBOX_CLASH_API_PORT}",
            },
        },
    }


def _build_native_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
) -> dict[str, Any]:
    proxy_outbound = _convert_outbound(deepcopy(node.outbound))
    proxy_outbound["tag"] = "proxy"
    proxy_outbound["domain_resolver"] = "proxy-dns"

    direct_out: dict[str, Any] = {"type": "direct", "tag": "direct", "domain_resolver": "proxy-dns"}
    block_out: dict[str, Any] = {"type": "block", "tag": "block"}

    outbounds = [proxy_outbound, direct_out, block_out]

    route_rules = _build_route_rules(routing, node)

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": f"xftun{os.getpid() % 10000}",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniff": True,
                "sniff_override_destination": True,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": "proxy-dns",
            "rules": route_rules,
        },
        "dns": {
            "servers": [
                {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1", "detour": "proxy"},
            ],
            "final": "proxy-dns",
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{SINGBOX_CLASH_API_PORT}",
            },
        },
    }


# ---------------------------------------------------------------------------
# Outbound conversion
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
        # Xray's xhttp/splithttp is not supported by sing-box.
        # Mark so the caller can use xray+tun hybrid mode.
        sb["_unsupported_transport"] = "xhttp"


# ---------------------------------------------------------------------------
# Routing rules
# ---------------------------------------------------------------------------

def _build_route_rules(routing: RoutingSettings, node: Node) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    # DNS hijack (sing-box 1.11+ action-based)
    rules.append({"protocol": "dns", "action": "hijack-dns"})

    # Bypass proxy server IP and DNS servers to prevent routing loops
    bypass_ips = ["8.8.8.8/32", "8.8.4.4/32", "1.1.1.1/32"]
    if node.server:
        bypass_ips.append(f"{node.server}/32")
    rules.append({"ip_cidr": bypass_ips, "outbound": "direct"})

    if routing.bypass_lan:
        rules.append({"ip_is_private": True, "outbound": "direct"})

    _append_singbox_rules(rules, routing.direct_domains, "direct")
    _append_singbox_rules(rules, routing.block_domains, "block")
    _append_singbox_rules(rules, routing.proxy_domains, "proxy")

    # Process-based routing (sing-box detects originating process via OS APIs)
    _append_process_rules(rules, routing)

    mode = routing.mode
    if mode == ROUTING_DIRECT:
        rules.append({"inbound": ["tun-in"], "outbound": "direct"})
    # For global and rule mode, default outbound is proxy (first outbound)

    return rules


def _append_process_rules(rules: list[dict[str, Any]], routing: RoutingSettings) -> None:
    """Group process rules by action and append as sing-box process_name rules."""
    proc_by_action: dict[str, list[str]] = {}
    for pr in routing.process_rules:
        name = pr.get("process", "").strip()
        action = pr.get("action", "proxy")
        if name and action in ("direct", "proxy", "block"):
            proc_by_action.setdefault(action, []).append(name)
    for action, names in proc_by_action.items():
        rules.append({"process_name": names, "outbound": action})


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
            # geosite/geoip removed in sing-box 1.12+, skip
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


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _build_dns(routing: RoutingSettings) -> dict[str, Any]:
    return {
        "servers": [
            {
                "tag": "proxy-dns",
                "type": "https",
                "server": "1.1.1.1",
                "detour": "proxy",
            },
            {
                "tag": "direct-dns",
                "type": "udp",
                "server": "8.8.8.8",
                "detour": "direct",
            },
        ],
        "final": "proxy-dns",
        "strategy": "prefer_ipv4",
    }
