from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...app_controller import AppController
    from ...application.session_state import XrayRuntimeConfig
    from ...models import Node


@dataclass(slots=True)
class XrayStartResult:
    runtime: XrayRuntimeConfig
    session_label: str


def start_tun(
    controller: AppController,
    node: Node | None,
    *,
    prev_active_core: str,
) -> XrayStartResult | None:
    controller._active_core = "xray"
    try:
        runtime = controller._build_runtime_xray_config(node, tun_mode=True)
    except ValueError as exc:
        controller._active_core = prev_active_core
        controller._set_connection_status("error", str(exc), level="error")
        return None

    session_label = runtime.source_path.name
    if runtime.used_selected_node and node is not None:
        session_label = f"{runtime.source_path.name} / {node.name}"
    controller._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")
    controller._log(f"[tun] starting xray TUN from {runtime.source_path}")
    if runtime.used_selected_node and node is not None:
        controller._log(f"[tun] outbound tag 'proxy' replaced from selected node: {node.name}")
    if runtime.loop_prevention_patched_outbounds > 0:
        controller._log(
            "[tun] xray loop prevention bound "
            f"{runtime.loop_prevention_patched_outbounds} outbound(s) to interface "
            f"{runtime.loop_prevention_interface}"
        )

    controller._xray_api_port = runtime.api_port
    if not controller.xray.start(controller.state.settings.xray_path, runtime.config):
        controller._active_core = prev_active_core
        return None
    route_ok = controller._xray_tun_routes.setup(runtime.tun_interface_name)
    if not route_ok:
        controller.xray.stop()
        controller._set_connection_status(
            "error",
            "Не удалось применить системный маршрут для Xray TUN. "
            "Проверьте права Администратора и версию Xray-core с native TUN support.",
            level="error",
        )
        controller._active_core = prev_active_core
        return None

    return XrayStartResult(runtime=runtime, session_label=session_label)


def start_proxy(
    controller: AppController,
    node: Node | None,
    *,
    prev_active_core: str,
) -> XrayStartResult | None:
    controller._active_core = "xray"
    try:
        runtime = controller._build_runtime_xray_config(node, tun_mode=False)
    except ValueError as exc:
        controller._active_core = prev_active_core
        controller._set_connection_status("error", str(exc), level="error")
        return None

    session_label = runtime.source_path.name
    if runtime.used_selected_node and node is not None:
        session_label = f"{runtime.source_path.name} / {node.name}"
    controller._set_connection_status("starting", f"Запуск прокси: {session_label}...", level="info")
    if runtime.used_selected_node and node is not None:
        controller._log(f"[xray] outbound tag 'proxy' replaced from selected node: {node.name}")

    controller._xray_api_port = runtime.api_port
    if not controller.xray.start(controller.state.settings.xray_path, runtime.config):
        controller._active_core = prev_active_core
        return None

    if controller.state.settings.enable_system_proxy:
        if runtime.http_port <= 0 or runtime.socks_port <= 0:
            controller.xray.stop()
            controller._set_connection_status(
                "error",
                "В raw xray config нет HTTP/SOCKS inbound портов для включения системного прокси.",
                level="error",
            )
            controller._active_core = prev_active_core
            return None
        try:
            controller.proxy.enable(
                runtime.http_port,
                runtime.socks_port,
                bypass_lan=controller._system_proxy_bypass_lan(),
            )
        except Exception as exc:
            controller.xray.stop()
            controller._set_connection_status("error", f"Не удалось включить системный прокси: {exc}", level="error")
            controller._active_core = prev_active_core
            return None
    else:
        controller.proxy.disable(restore_previous=True)

    return XrayStartResult(runtime=runtime, session_label=session_label)


def restart_proxy_core(controller: AppController, reason: str) -> bool:
    node = controller.selected_node
    controller._switching = True
    try:
        controller._log(f"[proxy-hot-swap] {reason}")
        try:
            runtime = controller._build_runtime_xray_config(node, tun_mode=False)
        except ValueError as exc:
            controller._set_connection_status("error", str(exc), level="error")
            return False

        session_label = runtime.source_path.name
        if runtime.used_selected_node and node is not None:
            session_label = f"{runtime.source_path.name} / {node.name}"
        controller._set_connection_status("starting", f"Переключение на {session_label}...", level="info")
        controller._stop_metrics_worker()
        if controller.xray.is_running and not controller.xray.stop():
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
            return False

        controller._xray_api_port = runtime.api_port
        ok = controller.xray.start(controller.state.settings.xray_path, runtime.config)
        if not ok:
            controller._handle_unexpected_disconnect()
            return False

        if controller.state.settings.enable_system_proxy:
            if runtime.http_port <= 0 or runtime.socks_port <= 0:
                controller.xray.stop()
                controller._set_connection_status(
                    "error",
                    "В raw xray config нет HTTP/SOCKS inbound портов для включения системного прокси.",
                    level="error",
                )
                controller._handle_unexpected_disconnect()
                return False
            try:
                controller.proxy.enable(
                    runtime.http_port,
                    runtime.socks_port,
                    bypass_lan=controller._system_proxy_bypass_lan(),
                )
            except Exception as exc:
                controller.xray.stop()
                controller._set_connection_status(
                    "error",
                    f"Не удалось включить системный прокси: {exc}",
                    level="error",
                )
                controller._handle_unexpected_disconnect()
                return False
        else:
            controller.proxy.disable(restore_previous=True)

        session_node = node if runtime.used_selected_node else None
        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()
        controller._capture_active_session(
            session_node,
            tun=False,
            core="xray",
            api_port=controller._xray_api_port,
            socks_port=runtime.socks_port,
            http_port=runtime.http_port,
            xray_inbound_tags=runtime.inbound_tags,
            ping_host=runtime.ping_host,
            ping_port=runtime.ping_port,
        )
        controller._set_connection_status("running", f"Переключено: {session_label}", level="success")
        controller.save()
        return True
    finally:
        controller._switching = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()
