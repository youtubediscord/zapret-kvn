from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import TYPE_CHECKING, Any

from ..constants import PROXY_HOST, XRAY_TUN_DEFAULT_INTERFACE_NAME
from ..engines.xray import get_windows_default_route_context
from .connection_service import find_free_api_port
from .runtime_introspection import extract_xray_runtime_ports
from .runtime_security import strip_xray_proxy_inbounds
from .session_state import XrayRuntimeConfig

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


APP_METRICS_API_TAG = "__app_metrics_api"
APP_METRICS_API_INBOUND_TAG = "__app_metrics_api_in"
APP_TUN_INBOUND_TAG = "__app_tun_in"


def inspect_active_xray_config(controller: AppController) -> tuple:
    path, text = controller.load_active_xray_config_text()
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = False
    socks_port = 0
    http_port = 0
    api_port = 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if payload is not None:
        ensure_xray_metrics_contract(controller, payload, allocate_port=False)
        has_proxy_outbound = controller._config_has_proxy_outbound(payload)
        socks_port, http_port, api_port = extract_xray_runtime_ports(payload)
    return path, text_hash, has_proxy_outbound, socks_port, http_port, api_port


def ensure_xray_metrics_contract(
    controller: AppController,
    payload: dict[str, Any],
    *,
    allocate_port: bool,
) -> tuple[int, tuple[str, ...]]:
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        payload["stats"] = {}

    policy = controller._ensure_dict(payload, "policy")
    system_policy = controller._ensure_dict(policy, "system")
    system_policy["statsInboundUplink"] = True
    system_policy["statsInboundDownlink"] = True
    system_policy["statsOutboundUplink"] = True
    system_policy["statsOutboundDownlink"] = True

    outbounds = controller._ensure_list(payload, "outbounds")
    api = controller._ensure_dict(payload, "api")
    existing_api_tag = str(api.get("tag") or "").strip()
    api_tag = APP_METRICS_API_TAG
    if existing_api_tag:
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            if str(outbound.get("tag") or "").strip() != existing_api_tag:
                continue
            protocol = str(outbound.get("protocol") or "").strip().lower()
            if protocol in {"freedom", "loopback"}:
                api_tag = existing_api_tag
            break
    api["tag"] = api_tag
    services = api.get("services")
    normalized_services = [str(item) for item in services] if isinstance(services, list) else []
    if "StatsService" not in normalized_services:
        normalized_services.append("StatsService")
    api["services"] = normalized_services

    inbounds = controller._ensure_list(payload, "inbounds")
    existing_ports = controller._collect_xray_inbound_ports(payload)

    preferred_api_port = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("tag") or "") != APP_METRICS_API_INBOUND_TAG:
            continue
        try:
            preferred_api_port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            preferred_api_port = 0
        if preferred_api_port > 0:
            existing_ports.discard(preferred_api_port)
        break

    if preferred_api_port > 0:
        api_port = preferred_api_port
    elif allocate_port:
        try:
            api_port = find_free_api_port(excluded=existing_ports)
        except RuntimeError as exc:
            raise ValueError("Не удалось выделить локальный порт для Xray metrics API.") from exc
    else:
        api_port = 0

    metrics_inbound = {
        "tag": APP_METRICS_API_INBOUND_TAG,
        "listen": PROXY_HOST,
        "port": api_port,
        "protocol": "dokodemo-door",
        "settings": {"address": PROXY_HOST},
    }
    controller._replace_or_append_tagged(inbounds, APP_METRICS_API_INBOUND_TAG, metrics_inbound)

    has_api_outbound = any(
        isinstance(outbound, dict) and str(outbound.get("tag") or "") == api_tag
        for outbound in outbounds
    )
    if not has_api_outbound:
        outbounds.append({"tag": api_tag, "protocol": "freedom", "settings": {}})

    user_inbound_tags: list[str] = []
    for index, inbound in enumerate(inbounds):
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get("tag") or "").strip()
        if tag == APP_METRICS_API_INBOUND_TAG:
            continue
        if not tag:
            tag = f"__app_user_inbound_{index}"
            inbound["tag"] = tag
        if tag not in user_inbound_tags:
            user_inbound_tags.append(tag)

    routing = controller._ensure_dict(payload, "routing")
    rules = controller._ensure_list(routing, "rules")
    metrics_rule = {
        "type": "field",
        "inboundTag": [APP_METRICS_API_INBOUND_TAG],
        "outboundTag": api_tag,
    }
    replaced = False
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_tags = rule.get("inboundTag")
        if isinstance(inbound_tags, list) and APP_METRICS_API_INBOUND_TAG in [str(item) for item in inbound_tags]:
            rules[index] = metrics_rule
            replaced = True
            break
    if not replaced:
        rules.insert(0, metrics_rule)

    return api_port, tuple(user_inbound_tags)


def ensure_xray_tun_contract(controller: AppController, payload: dict[str, Any]) -> str:
    inbounds = controller._ensure_list(payload, "inbounds")
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol") or "").strip().lower() != "tun":
            continue
        settings = controller._ensure_dict(inbound, "settings")
        return str(settings.get("name") or "").strip() or XRAY_TUN_DEFAULT_INTERFACE_NAME

    inbounds.append(
        {
            "tag": APP_TUN_INBOUND_TAG,
            "protocol": "tun",
            "settings": {},
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": True,
            },
        }
    )
    return XRAY_TUN_DEFAULT_INTERFACE_NAME


def xray_outbound_is_loop_protected(outbound: dict[str, Any]) -> bool:
    send_through = str(outbound.get("sendThrough") or "").strip()
    if send_through and send_through not in {"0.0.0.0", "::"}:
        return True
    stream_settings = outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        return False
    sockopt = stream_settings.get("sockopt")
    if not isinstance(sockopt, dict):
        return False
    return bool(str(sockopt.get("interface") or "").strip())


def apply_xray_tun_loop_prevention(controller: AppController, payload: dict[str, Any], interface_alias: str) -> int:
    patched = 0
    outbounds = controller._ensure_list(payload, "outbounds")
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag") or "").strip()
        protocol = str(outbound.get("protocol") or "").strip().lower()
        if tag in {APP_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
            continue
        if xray_outbound_is_loop_protected(outbound):
            continue
        stream_settings = controller._ensure_dict(outbound, "streamSettings")
        sockopt = controller._ensure_dict(stream_settings, "sockopt")
        sockopt["interface"] = interface_alias
        patched += 1
    return patched


def build_runtime_xray_config(controller: AppController, node: Node | None = None, *, tun_mode: bool = False) -> XrayRuntimeConfig:
    source_path, text = controller.load_active_xray_config_text()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path.name}: {controller._format_json_error_message(text, exc)}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Корень xray config должен быть JSON-объектом.")

    tun_interface_name = ""
    if tun_mode:
        tun_interface_name = controller._ensure_xray_tun_contract(payload)
        strip_xray_proxy_inbounds(payload)

    api_port, inbound_tags = controller._ensure_xray_metrics_contract(payload, allocate_port=True)

    outbounds = payload.get("outbounds")
    has_proxy_outbound = False
    used_selected_node = False
    if isinstance(outbounds, list):
        for index, outbound in enumerate(outbounds):
            if not isinstance(outbound, dict) or outbound.get("tag") != "proxy":
                continue
            has_proxy_outbound = True
            if node is None:
                raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска xray.")
            problem = controller._prepare_node_for_runtime(node)
            if problem:
                raise ValueError(problem)
            proxy_outbound = deepcopy(node.outbound)
            proxy_outbound["tag"] = "proxy"
            outbounds[index] = proxy_outbound
            used_selected_node = True
            break

    loop_prevention_interface = ""
    loop_prevention_patched_outbounds = 0
    if tun_mode:
        needs_loop_patch = False
        if isinstance(outbounds, list):
            for outbound in outbounds:
                if not isinstance(outbound, dict):
                    continue
                tag = str(outbound.get("tag") or "").strip()
                protocol = str(outbound.get("protocol") or "").strip().lower()
                if tag in {APP_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
                    continue
                if not controller._xray_outbound_is_loop_protected(outbound):
                    needs_loop_patch = True
                    break
        if needs_loop_patch:
            context = get_windows_default_route_context()
            if context is None:
                raise ValueError(
                    "Не удалось определить активный сетевой интерфейс для xray TUN loop prevention. "
                    "Либо укажите streamSettings.sockopt.interface/sendThrough в raw xray config, "
                    "либо используйте sing-box TUN."
                )
            loop_prevention_interface = context.interface_alias
            loop_prevention_patched_outbounds = controller._apply_xray_tun_loop_prevention(payload, loop_prevention_interface)

    socks_port, http_port, _ = extract_xray_runtime_ports(payload)
    ping_host, ping_port = controller._infer_xray_ping_target(payload, node if used_selected_node else None)
    return XrayRuntimeConfig(
        config=payload,
        source_path=source_path,
        has_proxy_outbound=has_proxy_outbound,
        used_selected_node=used_selected_node,
        socks_port=socks_port,
        http_port=http_port,
        api_port=api_port,
        tun_interface_name=tun_interface_name,
        loop_prevention_interface=loop_prevention_interface,
        loop_prevention_patched_outbounds=loop_prevention_patched_outbounds,
        inbound_tags=inbound_tags,
        ping_host=ping_host,
        ping_port=ping_port,
    )
