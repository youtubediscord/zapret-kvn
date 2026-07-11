from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import socket
from typing import Any


DEFAULT_PROXY_PORT_SCAN_ATTEMPTS = 500


@dataclass(frozen=True, slots=True)
class PortPairSelection:
    requested_socks_port: int
    requested_http_port: int
    socks_port: int
    http_port: int

    @property
    def changed(self) -> bool:
        return (
            self.socks_port != self.requested_socks_port
            or self.http_port != self.requested_http_port
        )


@dataclass(frozen=True, slots=True)
class PortSelection:
    requested_port: int
    port: int

    @property
    def changed(self) -> bool:
        return self.port != self.requested_port


def select_available_port(
    port: int,
    *,
    is_port_available: Callable[[int], bool],
    max_attempts: int = DEFAULT_PROXY_PORT_SCAN_ATTEMPTS,
) -> PortSelection:
    requested_port = int(port)
    for attempt in range(max(1, int(max_attempts))):
        candidate = requested_port + attempt
        if not _valid_port(candidate):
            continue
        if is_port_available(candidate):
            return PortSelection(requested_port=requested_port, port=candidate)
    raise RuntimeError(f"No available TCP port found near {requested_port}")


def select_available_port_pair(
    socks_port: int,
    http_port: int,
    *,
    is_port_available: Callable[[int], bool],
    max_attempts: int = DEFAULT_PROXY_PORT_SCAN_ATTEMPTS,
) -> PortPairSelection:
    requested_socks_port = int(socks_port)
    requested_http_port = int(http_port)
    step = 2 if abs(requested_http_port - requested_socks_port) == 1 else 1

    for attempt in range(max(1, int(max_attempts))):
        candidate_socks = requested_socks_port + attempt * step
        candidate_http = requested_http_port + attempt * step
        if not _valid_port(candidate_socks) or not _valid_port(candidate_http):
            continue
        if candidate_socks == candidate_http:
            continue
        if is_port_available(candidate_socks) and is_port_available(candidate_http):
            return PortPairSelection(
                requested_socks_port=requested_socks_port,
                requested_http_port=requested_http_port,
                socks_port=candidate_socks,
                http_port=candidate_http,
            )

    raise RuntimeError(
        "No available SOCKS/HTTP TCP port pair found near "
        f"{requested_socks_port}/{requested_http_port}"
    )


def apply_proxy_port_auto_selection(
    payload: dict[str, Any],
    *,
    allowed_ports: set[int] | None = None,
    max_attempts: int = DEFAULT_PROXY_PORT_SCAN_ATTEMPTS,
) -> PortPairSelection | None:
    socks_inbound = _find_proxy_inbound(payload, "socks")
    http_inbound = _find_proxy_inbound(payload, "http")
    if socks_inbound is None or http_inbound is None:
        return None

    socks_port = _read_port(socks_inbound)
    http_port = _read_port(http_inbound)
    if socks_port <= 0 or http_port <= 0:
        return None

    excluded_ports = _other_inbound_ports(payload, socks_inbound, http_inbound)
    bind_hosts = {
        _inbound_bind_host(socks_inbound),
        _inbound_bind_host(http_inbound),
    }
    allowed_ports = set(allowed_ports or set())

    def port_available(port: int) -> bool:
        if port in excluded_ports:
            return False
        if port in allowed_ports:
            return True
        return all(is_tcp_port_bindable(host, port) for host in bind_hosts)

    selection = select_available_port_pair(
        socks_port,
        http_port,
        is_port_available=port_available,
        max_attempts=max_attempts,
    )
    if selection.changed:
        socks_inbound["port"] = selection.socks_port
        http_inbound["port"] = selection.http_port
    return selection


def is_tcp_port_bindable(host: str, port: int) -> bool:
    bind_host = _normalize_bind_host(host)
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((bind_host, int(port)))
        return True
    except OSError:
        return False


def _normalize_bind_host(host: str) -> str:
    value = str(host or "").strip()
    if not value:
        return "127.0.0.1"
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if value.lower() == "localhost":
        return "127.0.0.1"
    return value


def _valid_port(port: int) -> bool:
    return 0 < int(port) <= 65535


def _find_proxy_inbound(payload: dict[str, Any], protocol: str) -> dict[str, Any] | None:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return None
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol") or "").strip().lower() == protocol:
            return inbound
    return None


def _read_port(inbound: dict[str, Any]) -> int:
    try:
        return int(inbound.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def _inbound_bind_host(inbound: dict[str, Any]) -> str:
    return _normalize_bind_host(str(inbound.get("listen") or ""))


def _other_inbound_ports(
    payload: dict[str, Any],
    socks_inbound: dict[str, Any],
    http_inbound: dict[str, Any],
) -> set[int]:
    ports: set[int] = set()
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return ports
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if inbound is socks_inbound or inbound is http_inbound:
            continue
        port = _read_port(inbound)
        if port > 0:
            ports.add(port)
    return ports
