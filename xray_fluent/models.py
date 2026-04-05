from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

from .constants import ROUTING_RULE, STATE_SCHEMA_VERSION


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Node:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    scheme: str = ""
    server: str = ""
    port: int = 0
    link: str = ""
    outbound: dict[str, Any] = field(default_factory=dict)
    group: str = "Default"
    tags: list[str] = field(default_factory=list)
    ping_ms: int | None = None
    last_used_at: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    country_code: str = ""
    speed_mbps: float | None = None
    is_alive: bool | None = None
    ping_history: list[tuple[str, int | None]] = field(default_factory=list)
    speed_history: list[tuple[str, float | None]] = field(default_factory=list)
    sort_order: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "scheme": self.scheme,
            "server": self.server,
            "port": self.port,
            "link": self.link,
            "outbound": self.outbound,
            "group": self.group,
            "tags": list(self.tags),
            "ping_ms": self.ping_ms,
            "last_used_at": self.last_used_at,
            "created_at": self.created_at,
            "country_code": self.country_code,
            "speed_mbps": self.speed_mbps,
            "is_alive": self.is_alive,
            "ping_history": self.ping_history,
            "speed_history": self.speed_history,
            "sort_order": self.sort_order,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Node":
        return Node(
            id=str(data.get("id") or uuid.uuid4()),
            name=str(data.get("name") or ""),
            scheme=str(data.get("scheme") or ""),
            server=str(data.get("server") or ""),
            port=int(data.get("port") or 0),
            link=str(data.get("link") or ""),
            outbound=dict(data.get("outbound") or {}),
            group=str(data.get("group") or "Default"),
            tags=list(data.get("tags") or []),
            ping_ms=data.get("ping_ms"),
            last_used_at=data.get("last_used_at"),
            created_at=str(data.get("created_at") or utc_now_iso()),
            country_code=str(data.get("country_code") or ""),
            speed_mbps=data.get("speed_mbps"),
            is_alive=data.get("is_alive"),
            ping_history=data.get("ping_history", []),
            speed_history=data.get("speed_history", []),
            sort_order=int(data.get("sort_order", 0)),
        )


@dataclass(slots=True)
class RoutingSettings:
    mode: str = ROUTING_RULE
    bypass_lan: bool = True
    direct_domains: list[str] = field(default_factory=list)
    proxy_domains: list[str] = field(default_factory=list)
    block_domains: list[str] = field(default_factory=list)
    dns_mode: str = "system"  # system | builtin
    dns_bootstrap_server: str = "1.1.1.1"  # DNS for direct traffic
    dns_bootstrap_type: str = "udp"        # udp | tcp | tls | https
    dns_proxy_server: str = "8.8.8.8"     # DNS for proxy traffic
    dns_proxy_type: str = "tcp"            # tcp | tls | https
    process_rules: list[dict[str, str]] = field(default_factory=list)  # [{"process": "chrome.exe", "action": "direct|proxy|block"}]
    process_preset_routes: dict[str, str] = field(default_factory=dict)  # {"telegram": "proxy", "windows_system": "direct"}
    service_routes: dict[str, str] = field(default_factory=dict)  # {"youtube": "proxy", "steam": "direct", ...}
    tun_default_outbound: str = "direct"  # "proxy" | "direct"

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "bypass_lan": self.bypass_lan,
            "direct_domains": list(self.direct_domains),
            "proxy_domains": list(self.proxy_domains),
            "block_domains": list(self.block_domains),
            "dns_mode": self.dns_mode,
            "dns_bootstrap_server": self.dns_bootstrap_server,
            "dns_bootstrap_type": self.dns_bootstrap_type,
            "dns_proxy_server": self.dns_proxy_server,
            "dns_proxy_type": self.dns_proxy_type,
            "process_rules": list(self.process_rules),
            "process_preset_routes": dict(self.process_preset_routes),
            "service_routes": dict(self.service_routes),
            "tun_default_outbound": self.tun_default_outbound,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RoutingSettings":
        return RoutingSettings(
            mode=str(data.get("mode") or ROUTING_RULE),
            bypass_lan=bool(data.get("bypass_lan", True)),
            direct_domains=list(data.get("direct_domains") or []),
            proxy_domains=list(data.get("proxy_domains") or []),
            block_domains=list(data.get("block_domains") or []),
            dns_mode=str(data.get("dns_mode") or "system"),
            dns_bootstrap_server=str(data.get("dns_bootstrap_server") or "1.1.1.1"),
            dns_bootstrap_type=str(data.get("dns_bootstrap_type") or "udp"),
            dns_proxy_server=str(data.get("dns_proxy_server") or "8.8.8.8"),
            dns_proxy_type=str(data.get("dns_proxy_type") or "tcp"),
            process_rules=list(data.get("process_rules") or []),
            process_preset_routes=dict(data.get("process_preset_routes") or {}),
            service_routes=dict(data.get("service_routes") or {}),
            tun_default_outbound=str(data.get("tun_default_outbound") or "direct"),
        )


@dataclass(slots=True)
class SecuritySettings:
    enabled: bool = False
    password_hash: str = ""
    salt: str = ""
    auto_lock_minutes: int = 15

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "password_hash": self.password_hash,
            "salt": self.salt,
            "auto_lock_minutes": self.auto_lock_minutes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SecuritySettings":
        return SecuritySettings(
            enabled=bool(data.get("enabled", False)),
            password_hash=str(data.get("password_hash") or ""),
            salt=str(data.get("salt") or ""),
            auto_lock_minutes=int(data.get("auto_lock_minutes") or 15),
        )


@dataclass(slots=True)
class AppSettings:
    theme: str = "system"  # system | light | dark
    accent_color: str = "#0078D4"
    auto_connect_last: bool = True
    start_minimized: bool = False
    launch_in_tray: bool = True
    enable_system_proxy: bool = True
    system_proxy_bypass_lan: bool = True
    launch_on_startup: bool = False
    reconnect_on_network_change: bool = True
    xray_path: str = ""
    log_level: str = "warning"
    check_updates: bool = True
    allow_updates: bool = True
    release_channel: str = "stable"  # stable | beta | nightly
    update_feed_url: str = ""
    xray_release_channel: str = "stable"  # stable | beta | nightly
    xray_update_feed_url: str = ""
    xray_auto_update: bool = False
    tun_mode: bool = False
    tun_engine: str = "singbox"  # "singbox" | "xray" | legacy "tun2socks"
    xray_config_file: str = ""
    xray_template_file: str = ""
    singbox_path: str = ""
    singbox_config_file: str = ""
    singbox_template_file: str = ""
    window_width: int = 1000
    window_height: int = 720
    window_x: int = -1
    window_y: int = -1
    zapret_preset: str = ""
    zapret_autostart: bool = False
    auto_switch_enabled: bool = True
    auto_switch_threshold_kbps: int = 50
    auto_switch_delay_sec: int = 30
    auto_switch_cooldown_sec: int = 60

    def to_dict(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "accent_color": self.accent_color,
            "auto_connect_last": self.auto_connect_last,
            "start_minimized": self.start_minimized,
            "launch_in_tray": self.launch_in_tray,
            "enable_system_proxy": self.enable_system_proxy,
            "system_proxy_bypass_lan": self.system_proxy_bypass_lan,
            "launch_on_startup": self.launch_on_startup,
            "reconnect_on_network_change": self.reconnect_on_network_change,
            "xray_path": self.xray_path,
            "log_level": self.log_level,
            "check_updates": self.check_updates,
            "allow_updates": self.allow_updates,
            "release_channel": self.release_channel,
            "update_feed_url": self.update_feed_url,
            "xray_release_channel": self.xray_release_channel,
            "xray_update_feed_url": self.xray_update_feed_url,
            "xray_auto_update": self.xray_auto_update,
            "tun_mode": self.tun_mode,
            "tun_engine": self.tun_engine,
            "xray_config_file": self.xray_config_file,
            "xray_template_file": self.xray_template_file,
            "singbox_path": self.singbox_path,
            "singbox_config_file": self.singbox_config_file,
            "singbox_template_file": self.singbox_template_file,
            "window_width": self.window_width,
            "window_height": self.window_height,
            "window_x": self.window_x,
            "window_y": self.window_y,
            "zapret_preset": self.zapret_preset,
            "zapret_autostart": self.zapret_autostart,
            "auto_switch_enabled": self.auto_switch_enabled,
            "auto_switch_threshold_kbps": self.auto_switch_threshold_kbps,
            "auto_switch_delay_sec": self.auto_switch_delay_sec,
            "auto_switch_cooldown_sec": self.auto_switch_cooldown_sec,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppSettings":
        return AppSettings(
            theme=str(data.get("theme") or "system"),
            accent_color=str(data.get("accent_color") or "#0078D4"),
            auto_connect_last=bool(data.get("auto_connect_last", True)),
            start_minimized=bool(data.get("start_minimized", False)),
            launch_in_tray=bool(data.get("launch_in_tray", True)),
            enable_system_proxy=bool(data.get("enable_system_proxy", True)),
            system_proxy_bypass_lan=bool(data.get("system_proxy_bypass_lan", True)),
            launch_on_startup=bool(data.get("launch_on_startup", False)),
            reconnect_on_network_change=bool(data.get("reconnect_on_network_change", True)),
            xray_path=str(data.get("xray_path") or ""),
            log_level=str(data.get("log_level") or "warning"),
            check_updates=bool(data.get("check_updates", True)),
            allow_updates=bool(data.get("allow_updates", True)),
            release_channel=str(data.get("release_channel") or "stable"),
            update_feed_url=str(data.get("update_feed_url") or ""),
            xray_release_channel=str(data.get("xray_release_channel") or "stable"),
            xray_update_feed_url=str(data.get("xray_update_feed_url") or ""),
            xray_auto_update=bool(data.get("xray_auto_update", False)),
            tun_mode=bool(data.get("tun_mode", False)),
            tun_engine=str(data.get("tun_engine") or "singbox"),
            xray_config_file=str(data.get("xray_config_file") or ""),
            xray_template_file=str(data.get("xray_template_file") or ""),
            singbox_path=str(data.get("singbox_path") or ""),
            singbox_config_file=str(data.get("singbox_config_file") or ""),
            singbox_template_file=str(data.get("singbox_template_file") or ""),
            window_width=int(data.get("window_width") or 1000),
            window_height=int(data.get("window_height") or 720),
            window_x=int(data.get("window_x", -1)),
            window_y=int(data.get("window_y", -1)),
            zapret_preset=str(data.get("zapret_preset") or ""),
            zapret_autostart=bool(data.get("zapret_autostart", False)),
            auto_switch_enabled=bool(data.get("auto_switch_enabled", True)),
            auto_switch_threshold_kbps=int(data.get("auto_switch_threshold_kbps") or 50),
            auto_switch_delay_sec=int(data.get("auto_switch_delay_sec") or 30),
            auto_switch_cooldown_sec=int(data.get("auto_switch_cooldown_sec") or 60),
        )


@dataclass(slots=True)
class AppState:
    schema_version: int = STATE_SCHEMA_VERSION
    selected_node_id: str | None = None
    nodes: list[Node] = field(default_factory=list)
    routing: RoutingSettings = field(default_factory=RoutingSettings)
    settings: AppSettings = field(default_factory=AppSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "selected_node_id": self.selected_node_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "routing": self.routing.to_dict(),
            "settings": self.settings.to_dict(),
            "security": self.security.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AppState":
        nodes_raw = data.get("nodes") or []
        nodes = [Node.from_dict(item) for item in nodes_raw if isinstance(item, dict)]
        return AppState(
            schema_version=int(data.get("schema_version") or STATE_SCHEMA_VERSION),
            selected_node_id=data.get("selected_node_id"),
            nodes=nodes,
            routing=RoutingSettings.from_dict(dict(data.get("routing") or {})),
            settings=AppSettings.from_dict(dict(data.get("settings") or {})),
            security=SecuritySettings.from_dict(dict(data.get("security") or {})),
        )
