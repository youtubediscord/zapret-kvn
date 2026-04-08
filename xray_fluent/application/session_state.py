from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ActiveSessionSnapshot:
    node_id: str | None
    node_server: str
    active_core: str
    tun_mode: bool
    tun_engine: str
    proxy_enabled: bool
    proxy_bypass_lan: bool
    xray_path: str
    singbox_path: str
    socks_port: int
    http_port: int
    routing_signature: str
    transition_signature: str
    xray_layer_signature: str
    tun_layer_signature: str
    hybrid: bool
    api_port: int
    xray_inbound_tags: tuple[str, ...]
    sidecar_relay_port: int
    protect_ss_port: int
    protect_ss_password: str
    ping_host: str
    ping_port: int


@dataclass(slots=True)
class XrayRuntimeConfig:
    config: dict[str, Any]
    source_path: Path
    has_proxy_outbound: bool
    used_selected_node: bool
    socks_port: int
    http_port: int
    api_port: int
    tun_interface_name: str
    loop_prevention_interface: str
    loop_prevention_patched_outbounds: int
    inbound_tags: tuple[str, ...]
    ping_host: str
    ping_port: int


def build_active_session_snapshot(
    *,
    node_id: str | None,
    node_server: str,
    active_core: str,
    tun_mode: bool,
    tun_engine: str,
    proxy_enabled: bool,
    proxy_bypass_lan: bool,
    xray_path: str,
    singbox_path: str,
    socks_port: int,
    http_port: int,
    routing_signature: str,
    transition_signature: str,
    xray_layer_signature: str,
    tun_layer_signature: str,
    hybrid: bool,
    api_port: int,
    xray_inbound_tags: tuple[str, ...],
    sidecar_relay_port: int,
    protect_ss_port: int,
    protect_ss_password: str,
    ping_host: str,
    ping_port: int,
) -> ActiveSessionSnapshot:
    return ActiveSessionSnapshot(
        node_id=node_id,
        node_server=node_server,
        active_core=active_core,
        tun_mode=tun_mode,
        tun_engine=tun_engine,
        proxy_enabled=proxy_enabled,
        proxy_bypass_lan=proxy_bypass_lan,
        xray_path=xray_path,
        singbox_path=singbox_path,
        socks_port=socks_port,
        http_port=http_port,
        routing_signature=routing_signature,
        transition_signature=transition_signature,
        xray_layer_signature=xray_layer_signature,
        tun_layer_signature=tun_layer_signature,
        hybrid=hybrid,
        api_port=api_port,
        xray_inbound_tags=xray_inbound_tags,
        sidecar_relay_port=sidecar_relay_port,
        protect_ss_port=protect_ss_port,
        protect_ss_password=protect_ss_password,
        ping_host=ping_host,
        ping_port=ping_port,
    )
