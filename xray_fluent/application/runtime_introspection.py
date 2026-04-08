from __future__ import annotations

from typing import Any


def config_has_proxy_outbound(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return False
    return any(isinstance(outbound, dict) and outbound.get("tag") == "proxy" for outbound in outbounds)


def is_local_runtime_host(value: str) -> bool:
    host = str(value or "").strip().lower()
    return host in {"", "127.0.0.1", "::1", "localhost"}


def infer_singbox_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
    host = str(outbound.get("server") or "").strip()
    try:
        port = int(outbound.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not host or port <= 0 or is_local_runtime_host(host):
        return "", 0
    return host, port


def infer_xray_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
    protocol = str(outbound.get("protocol") or "").strip().lower()
    settings = outbound.get("settings")
    if not isinstance(settings, dict):
        return "", 0

    host = ""
    port = 0
    if protocol in {"vless", "vmess"}:
        vnext = settings.get("vnext")
        if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
            host = str(vnext[0].get("address") or "").strip()
            try:
                port = int(vnext[0].get("port") or 0)
            except (TypeError, ValueError):
                port = 0
    elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
        servers = settings.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            host = str(servers[0].get("address") or "").strip()
            try:
                port = int(servers[0].get("port") or 0)
            except (TypeError, ValueError):
                port = 0

    if not host or port <= 0 or is_local_runtime_host(host):
        return "", 0
    return host, port


def infer_singbox_ping_target(payload: dict[str, Any], node) -> tuple[str, int]:
    if node is not None and node.server and node.port > 0:
        return node.server, node.port
    for outbound in payload.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        host, port = infer_singbox_outbound_endpoint(outbound)
        if host and port > 0:
            return host, port
    return "", 0


def infer_xray_ping_target(payload: dict[str, Any], node) -> tuple[str, int]:
    if node is not None and node.server and node.port > 0:
        return node.server, node.port
    for outbound in payload.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        host, port = infer_xray_outbound_endpoint(outbound)
        if host and port > 0:
            return host, port
    return "", 0


def ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    created: dict[str, Any] = {}
    parent[key] = created
    return created


def ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    created: list[Any] = []
    parent[key] = created
    return created


def replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
    for index, item in enumerate(items):
        if isinstance(item, dict) and str(item.get("tag") or "") == tag:
            items[index] = payload
            return
    items.append(payload)


def collect_xray_inbound_ports(payload: Any) -> set[int]:
    ports: set[int] = set()
    if not isinstance(payload, dict):
        return ports
    for inbound in payload.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        try:
            port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port > 0:
            ports.add(port)
    return ports


def extract_xray_runtime_ports(payload: Any) -> tuple[int, int, int]:
    socks_port = 0
    http_port = 0
    api_port = 0
    mixed_port = 0
    if not isinstance(payload, dict):
        return socks_port, http_port, api_port
    for inbound in payload.get("inbounds") or []:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol") or "").strip().lower()
        tag = str(inbound.get("tag") or "").strip().lower()
        port_raw = inbound.get("port")
        try:
            port = int(port_raw or 0)
        except (TypeError, ValueError):
            port = 0
        if port <= 0:
            continue
        if protocol == "socks" and socks_port <= 0:
            socks_port = port
        elif protocol == "http" and http_port <= 0:
            http_port = port
        elif protocol == "mixed" and mixed_port <= 0:
            mixed_port = port
        elif tag == "api" and api_port <= 0:
            api_port = port
        elif tag == "__app_metrics_api_in" and api_port <= 0:
            api_port = port
    if socks_port <= 0 and mixed_port > 0:
        socks_port = mixed_port
    if http_port <= 0 and mixed_port > 0:
        http_port = mixed_port
    return socks_port, http_port, api_port
