from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT
from ..engines.singbox import classify_node_for_singbox

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import AppSettings, Node, RoutingSettings


def signature(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def routing_signature(controller: AppController, routing: RoutingSettings | None = None) -> str:
    routing = routing or controller.state.routing
    return signature(routing.to_dict())


def system_proxy_bypass_lan(controller: AppController, settings: AppSettings | None = None) -> bool:
    settings = settings or controller.state.settings
    return bool(settings.system_proxy_bypass_lan)


def _singbox_runtime_signature_payload(
    controller: AppController,
    node: Node | None,
    settings: AppSettings,
) -> dict[str, object]:
    source_path, config_hash, has_proxy_outbound = controller._inspect_active_singbox_config()
    planner_outcome = "native_singbox"
    if has_proxy_outbound and node is not None:
        planner_outcome = classify_node_for_singbox(node)
    payload: dict[str, object] = {
        "mode": "singbox-tun" if controller.is_singbox_tun_mode(settings) else "singbox-proxy",
        "singbox_path": str(settings.singbox_path),
        "config_file": str(source_path.name),
        "config_hash": config_hash,
        "has_proxy_outbound": has_proxy_outbound,
        "planner_outcome": planner_outcome,
        "node_id": node.id if has_proxy_outbound and node else None,
        "node_outbound": node.outbound if has_proxy_outbound and node else None,
    }
    if planner_outcome == "hybrid_xray_sidecar":
        payload["xray_path"] = str(settings.xray_path)
    if controller.is_singbox_proxy_mode(settings):
        payload.update(
            {
                "proxy_engine": "singbox",
                "socks_port": int(DEFAULT_SOCKS_PORT),
                "http_port": int(DEFAULT_HTTP_PORT),
            }
        )
    return payload


def transition_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = node or controller.selected_node
    if controller.is_singbox_editor_mode(settings):
        signature_payload = _singbox_runtime_signature_payload(controller, node, settings)
        if controller.is_singbox_proxy_mode(settings):
            signature_payload.update(
                {
                    "proxy_enabled": bool(settings.enable_system_proxy),
                    "proxy_bypass_lan": system_proxy_bypass_lan(controller, settings),
                }
            )
        return signature(signature_payload)
    if controller.uses_xray_raw_config(settings):
        source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = controller._inspect_active_xray_config()
        signature_payload = {
            "mode": "xray-tun" if controller.is_xray_tun_mode(settings) else "xray-direct",
            "proxy_engine": "xray" if not settings.tun_mode else None,
            "xray_path": str(settings.xray_path),
            "config_file": str(source_path.name),
            "config_hash": config_hash,
            "has_proxy_outbound": has_proxy_outbound,
            "node_id": node.id if has_proxy_outbound and node else None,
            "node_outbound": node.outbound if has_proxy_outbound and node else None,
            "api_port": int(api_port),
        }
        if controller.is_xray_tun_mode(settings):
            signature_payload.update({"tun_mode": True, "tun_engine": "xray"})
        else:
            signature_payload.update(
                {
                    "proxy_enabled": bool(settings.enable_system_proxy),
                    "proxy_bypass_lan": system_proxy_bypass_lan(controller, settings),
                    "socks_port": int(socks_port),
                    "http_port": int(http_port),
                }
            )
        return signature(signature_payload)
    return signature(
        {
            "node_id": node.id if node else None,
            "tun_mode": bool(settings.tun_mode),
            "tun_engine": str(settings.tun_engine),
            "proxy_enabled": bool(settings.enable_system_proxy),
            "proxy_bypass_lan": bool(routing.bypass_lan),
            "socks_port": int(DEFAULT_SOCKS_PORT),
            "http_port": int(DEFAULT_HTTP_PORT),
            "xray_path": str(settings.xray_path),
            "singbox_path": str(settings.singbox_path),
            "routing": routing.to_dict(),
        }
    )


def xray_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = node or controller.selected_node
    if controller.is_singbox_proxy_mode(settings):
        return signature(_singbox_runtime_signature_payload(controller, node, settings))
    if controller.uses_xray_raw_config(settings):
        source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = controller._inspect_active_xray_config()
        signature_payload = {
            "mode": "xray-tun" if controller.is_xray_tun_mode(settings) else "xray-direct",
            "xray_path": str(settings.xray_path),
            "config_file": str(source_path.name),
            "config_hash": config_hash,
            "has_proxy_outbound": has_proxy_outbound,
            "node_id": node.id if has_proxy_outbound and node else None,
            "node_outbound": node.outbound if has_proxy_outbound and node else None,
            "socks_port": int(socks_port),
            "http_port": int(http_port),
            "api_port": int(api_port),
        }
        if controller.is_xray_tun_mode(settings):
            signature_payload.update({"tun_mode": True, "tun_engine": "xray"})
        return signature(signature_payload)
    return signature(
        {
            "node_id": node.id if node else None,
            "tun_mode": bool(settings.tun_mode),
            "tun_engine": str(settings.tun_engine),
            "socks_port": int(DEFAULT_SOCKS_PORT),
            "http_port": int(DEFAULT_HTTP_PORT),
            "xray_path": str(settings.xray_path),
            "routing": routing.to_dict(),
        }
    )


def tun_layer_signature(
    controller: AppController,
    node: Node | None = None,
    settings: AppSettings | None = None,
    routing: RoutingSettings | None = None,
) -> str:
    settings = settings or controller.state.settings
    routing = routing or controller.state.routing
    node = node or controller.selected_node
    if not settings.tun_mode:
        return ""
    if controller.is_singbox_editor_mode(settings):
        return transition_signature(controller, node, settings, routing)
    if controller.is_tun2socks_mode(settings):
        return signature(
            {
                "mode": "tun2socks",
                "server": node.server if node else "",
                "socks_port": int(DEFAULT_SOCKS_PORT),
            }
        )
    if controller.is_xray_tun_mode(settings):
        return signature(
            {
                "mode": "xray-native-tun",
                "xray_layer_signature": xray_layer_signature(controller, node, settings, routing),
            }
        )
    return signature(
        {
            "mode": "singbox-native",
            "node_id": node.id if node else None,
            "node_outbound": (node.outbound if node else {}),
            "routing": routing.to_dict(),
            "xray_path": str(settings.xray_path),
            "singbox_path": str(settings.singbox_path),
        }
    )
