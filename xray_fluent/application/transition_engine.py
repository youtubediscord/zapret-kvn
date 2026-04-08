from __future__ import annotations

from dataclasses import dataclass

from .session_state import ActiveSessionSnapshot


@dataclass(slots=True)
class TransitionContext:
    desired_connected: bool
    locked: bool
    has_selected_node: bool
    can_connect_without_selected_node: bool
    connected: bool
    blocked_transition_signature: str
    current_transition_signature: str
    active_session: ActiveSessionSnapshot | None
    can_apply_proxy_runtime_change: bool
    can_tun_hot_swap: bool
    can_proxy_hot_swap: bool


def needs_transition(context: TransitionContext) -> bool:
    if context.desired_connected:
        if context.locked:
            return False
        if not context.has_selected_node and not context.can_connect_without_selected_node:
            return False
        if context.current_transition_signature == context.blocked_transition_signature:
            return False
        if not context.connected or context.active_session is None:
            return True
        return context.active_session.transition_signature != context.current_transition_signature
    return context.connected


def compute_transition_action(context: TransitionContext) -> str | None:
    if not context.desired_connected:
        return "disconnect" if context.connected else None
    if context.locked:
        return None
    if not context.has_selected_node and not context.can_connect_without_selected_node:
        return None
    if not context.connected or context.active_session is None:
        return "connect"
    if context.active_session.transition_signature == context.current_transition_signature:
        return None
    if context.can_apply_proxy_runtime_change:
        return "proxy_update"
    if context.can_tun_hot_swap:
        return "tun_hot_swap"
    if context.can_proxy_hot_swap:
        return "proxy_hot_swap"
    return "reconnect"


def transition_status_text(action: str) -> str:
    mapping = {
        "connect": "Подключение...",
        "disconnect": "Отключение...",
        "proxy_update": "Применение системного прокси...",
        "proxy_hot_swap": "Переключение сервера...",
        "tun_hot_swap": "Переключение сервера...",
        "reconnect": "Переподключение...",
    }
    return mapping.get(action, "Применение изменений...")


def can_apply_proxy_runtime_change(
    *,
    session: ActiveSessionSnapshot,
    settings_tun_mode: bool,
    current_xray_layer_signature: str,
    proxy_enabled: bool,
    proxy_bypass_lan: bool,
) -> bool:
    if session.active_core != "xray" or session.tun_mode or settings_tun_mode:
        return False
    if session.xray_layer_signature != current_xray_layer_signature:
        return False
    return session.proxy_enabled != proxy_enabled or session.proxy_bypass_lan != proxy_bypass_lan


def can_proxy_hot_swap(
    *,
    session: ActiveSessionSnapshot,
    settings_tun_mode: bool,
    socks_port: int,
    http_port: int,
    current_xray_layer_signature: str,
) -> bool:
    if session.active_core != "xray" or session.tun_mode or settings_tun_mode:
        return False
    if session.socks_port != int(socks_port) or session.http_port != int(http_port):
        return False
    return session.xray_layer_signature != current_xray_layer_signature


def can_tun_hot_swap(
    *,
    session: ActiveSessionSnapshot,
    settings_tun_mode: bool,
    settings_tun_engine: str,
    has_selected_node: bool,
    current_tun_layer_signature: str,
) -> bool:
    if not settings_tun_mode or not session.tun_mode:
        return False
    if session.tun_engine != settings_tun_engine:
        return False
    if session.active_core == "singbox":
        return settings_tun_engine == "singbox"
    if session.active_core == "tun2socks":
        if not has_selected_node or settings_tun_engine != "tun2socks":
            return False
        return session.tun_layer_signature == current_tun_layer_signature
    return False
