from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ...application.port_allocator import is_tcp_port_bindable, select_available_port
from ...runtime_security import (
    generate_local_proxy_credentials,
    set_xray_socks_inbound_auth,
    strip_xray_proxy_inbounds,
)
from ...constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, PROXY_HOST
from ..xray.config_builder import build_xray_config

if TYPE_CHECKING:
    from ...app_controller import AppController
    from ...models import Node


@dataclass(slots=True)
class Tun2SocksStartResult:
    session_label: str
    socks_port: int
    http_port: int = DEFAULT_HTTP_PORT


def _select_tun2socks_socks_port(controller: AppController, preferred: int) -> int:
    selection = select_available_port(
        preferred,
        is_port_available=lambda port: (
            port != controller._xray_api_port
            and is_tcp_port_bindable(PROXY_HOST, port)
        ),
    )
    if selection.changed:
        message = (
            "Локальный порт Xray relay изменён: "
            f"SOCKS {selection.requested_port} -> {selection.port}. "
            "Исходный порт занят или зарезервирован Windows."
        )
        controller._log(f"[tun] {message}")
        controller.status.emit("warning-long", message)
    return selection.port


def start_tun(
    controller: AppController,
    node: Node,
    *,
    prev_active_core: str,
) -> Tun2SocksStartResult | None:
    controller._active_core = "tun2socks"
    try:
        socks_port = _select_tun2socks_socks_port(controller, DEFAULT_SOCKS_PORT)
    except RuntimeError:
        controller._set_connection_status(
            "error",
            "Не удалось подобрать свободный локальный SOCKS порт для tun2socks.",
            level="error",
        )
        controller._active_core = prev_active_core
        return None
    config = build_xray_config(
        node,
        controller.state.routing,
        controller.state.settings,
        api_port=controller._xray_api_port,
        socks_port=socks_port,
        http_port=DEFAULT_HTTP_PORT,
    )
    config["log"] = {"loglevel": "error"}
    proxy_username = controller._tun2socks_proxy_username
    proxy_password = controller._tun2socks_proxy_password
    if not proxy_username or not proxy_password:
        proxy_username, proxy_password = generate_local_proxy_credentials(prefix="tun2socks")
        controller._tun2socks_proxy_username = proxy_username
        controller._tun2socks_proxy_password = proxy_password
    strip_xray_proxy_inbounds(config, keep_tags={"socks-in"})
    if not set_xray_socks_inbound_auth(
        config,
        tag="socks-in",
        username=proxy_username,
        password=proxy_password,
    ):
        controller._log("[tun] failed to secure internal SOCKS relay")
        controller._active_core = prev_active_core
        controller._tun2socks_proxy_username = ""
        controller._tun2socks_proxy_password = ""
        return None
    if not controller.xray.start(controller.state.settings.xray_path, config):
        controller._log("[tun] xray start failed")
        controller._active_core = prev_active_core
        controller._tun2socks_proxy_username = ""
        controller._tun2socks_proxy_password = ""
        return None
    controller._set_connection_status("starting", "Xray запущен. Создание TUN адаптера...", level="info")

    controller._log(f"[tun] starting tun2socks -> SOCKS 127.0.0.1:{socks_port}")
    tun_ok = controller.tun2socks.start(
        socks_port,
        username=proxy_username,
        password=proxy_password,
        server_ip=node.server,
    )
    controller._log(f"[tun] tun2socks start result: {tun_ok}")
    if not tun_ok:
        controller.xray.stop()
        controller._set_connection_status(
            "error",
            "Не удалось создать TUN адаптер. Проверьте наличие tun2socks и wintun.dll в core/.",
            level="error",
        )
        controller._active_core = prev_active_core
        controller._tun2socks_proxy_username = ""
        controller._tun2socks_proxy_password = ""
        return None
    return Tun2SocksStartResult(session_label=node.name, socks_port=socks_port)


def hot_swap(controller: AppController, reason: str, node: Node) -> bool:
    controller._switching = True
    try:
        problem = controller._prepare_node_for_runtime(node)
        if problem:
            controller._set_connection_status("error", problem, level="error")
            return False
        controller._log(f"[hot-swap] {reason} — restarting xray only, tun2socks stays up")
        controller._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
        controller.xray.stop()
        proxy_username = controller._tun2socks_proxy_username
        proxy_password = controller._tun2socks_proxy_password
        if not proxy_username or not proxy_password:
            controller._log("[hot-swap] missing tun2socks relay credentials")
            controller._set_connection_status(
                "error",
                "Не удалось безопасно перезапустить Xray: потеряны локальные credentials relay для tun2socks.",
                level="error",
            )
            return False
        active_session = controller._active_session
        socks_port = (
            int(active_session.socks_port)
            if active_session is not None and active_session.socks_port > 0
            else int(DEFAULT_SOCKS_PORT)
        )
        config = build_xray_config(
            node,
            controller.state.routing,
            controller.state.settings,
            api_port=controller._xray_api_port,
            socks_port=socks_port,
            http_port=DEFAULT_HTTP_PORT,
        )
        config["log"] = {"loglevel": "error"}
        strip_xray_proxy_inbounds(config, keep_tags={"socks-in"})
        if not set_xray_socks_inbound_auth(
            config,
            tag="socks-in",
            username=proxy_username,
            password=proxy_password,
        ):
            controller._set_connection_status(
                "error",
                "Не удалось безопасно пересобрать локальный SOCKS relay для tun2socks.",
                level="error",
            )
            return False
        ok = controller.xray.start(controller.state.settings.xray_path, config)
        if ok:
            node.last_used_at = datetime.now(timezone.utc).isoformat()
            controller._capture_active_session(
                node,
                tun=True,
                core="tun2socks",
                api_port=controller._xray_api_port,
                socks_port=socks_port,
                http_port=DEFAULT_HTTP_PORT,
                xray_inbound_tags=("socks-in", "http-in"),
                ping_host=node.server,
                ping_port=node.port,
            )
            controller._set_connection_status("running", f"Переключено: {node.name} (TUN)", level="success")
            controller.save()
        else:
            controller._log("[hot-swap] xray restart failed")
            controller._set_connection_status("error", "Не удалось переключить сервер, подключение остановлено", level="error")
            controller._handle_unexpected_disconnect()
        return ok
    finally:
        controller._switching = False
        controller._auto_switch_transitioning = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()
