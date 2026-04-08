from __future__ import annotations

import ctypes
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, DEFAULT_XRAY_STATS_API_PORT
from ..engines.singbox import SingboxRuntimePlan, start_tun as start_singbox_tun
from ..engines.tun2socks import hot_swap as hot_swap_tun2socks, start_tun as start_tun2socks_tun
from ..engines.xray import (
    restart_proxy_core as restart_xray_proxy_core,
    start_proxy as start_xray_proxy,
    start_tun as start_xray_tun,
)

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..application.session_state import XrayRuntimeConfig


def find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


def connect_selected(controller: AppController, allow_during_reconnect: bool = False) -> bool:
    if controller._connecting:
        return False
    controller._connecting = True
    try:
        if controller._reconnecting and not allow_during_reconnect:
            controller._set_connection_status("starting", "Переподключение...", level="info")
            return False

        if controller.locked:
            controller._set_connection_status(
                "error",
                "Приложение заблокировано. Разблокируйте для подключения.",
                level="warning",
            )
            return False

        node = controller.selected_node
        singbox_editor_mode = controller.is_singbox_editor_mode()
        xray_raw_mode = controller.uses_xray_raw_config()
        tun2socks_mode = controller.is_tun2socks_mode()
        if node is None and not controller._can_connect_without_selected_node():
            message = "Сначала выберите сервер."
            if singbox_editor_mode or xray_raw_mode:
                message = "В конфиге есть outbound tag `proxy`. Сначала выберите сервер."
            controller._set_connection_status("error", message, level="warning")
            return False

        controller._reset_auto_switch_state(
            reset_cooldown=not controller._auto_switch_transitioning,
            reset_cycle=not controller._auto_switch_transitioning,
        )

        prev_active_core = controller._active_core
        tun = controller.state.settings.tun_mode
        controller._xray_api_port = 0
        if tun2socks_mode:
            try:
                controller._xray_api_port = find_free_api_port(
                    excluded={DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT},
                )
            except RuntimeError:
                controller._set_connection_status("error", "Не удалось найти свободный порт для API Xray", level="error")
                return False

        singbox_plan: SingboxRuntimePlan | None = None
        runtime_xray: XrayRuntimeConfig | None = None
        if singbox_editor_mode:
            session_label = node.name if node else controller.get_active_singbox_config_name()
        elif xray_raw_mode:
            session_label = node.name if node else controller.get_active_xray_config_name()
        else:
            session_label = node.name if node else "unknown"

        if node is not None and not singbox_editor_mode and not xray_raw_mode:
            problem = controller._prepare_node_for_runtime(node)
            if problem:
                controller._set_connection_status("error", problem, level="error")
                return False

        if tun:
            controller._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
            controller._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")

            if not _is_admin():
                controller._log("[tun] NOT admin — aborting")
                controller._set_connection_status(
                    "error",
                    "Режим TUN требует прав Администратора. Запустите приложение от имени Администратора.",
                    level="error",
                )
                return False

            if controller.proxy.is_enabled():
                controller.proxy.disable(restore_previous=True)

            controller._tun_log_count = 0
            engine = controller.state.settings.tun_engine

            if engine == "singbox":
                result = start_singbox_tun(controller, node, prev_active_core=prev_active_core)
                if result is None:
                    return False
                singbox_plan = result.plan
                session_label = result.session_label
            elif engine == "xray":
                result = start_xray_tun(controller, node, prev_active_core=prev_active_core)
                if result is None:
                    return False
                runtime_xray = result.runtime
                session_label = result.session_label
            elif engine == "tun2socks":
                if node is None:
                    controller._active_core = prev_active_core
                    return False
                result = start_tun2socks_tun(controller, node, prev_active_core=prev_active_core)
                if result is None:
                    return False
                session_label = result.session_label
            else:
                controller._active_core = prev_active_core
                controller._set_connection_status("error", f"Неизвестный TUN engine: {engine}", level="error")
                return False
        else:
            result = start_xray_proxy(controller, node, prev_active_core=prev_active_core)
            if result is None:
                return False
            runtime_xray = result.runtime
            session_label = result.session_label

        session_node = node
        if singbox_editor_mode and singbox_plan is not None and not singbox_plan.used_selected_node:
            session_node = None
        if xray_raw_mode and runtime_xray is not None and not runtime_xray.used_selected_node:
            session_node = None

        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()

        controller._set_connection_status(
            "running",
            f"Подключено: {session_label}"
            + (
                " (TUN, xray sidecar)"
                if tun and singbox_plan is not None and singbox_plan.is_hybrid
                else " (TUN)" if tun else ""
            ),
            level="success",
        )
        controller._capture_active_session(
            session_node,
            tun=tun,
            core=controller._active_core,
            api_port=controller._xray_api_port,
            hybrid=bool(singbox_plan is not None and singbox_plan.is_hybrid),
            socks_port=runtime_xray.socks_port if runtime_xray is not None else None,
            http_port=runtime_xray.http_port if runtime_xray is not None else None,
            xray_inbound_tags=runtime_xray.inbound_tags if runtime_xray is not None else ("socks-in", "http-in"),
            sidecar_relay_port=singbox_plan.xray_sidecar.relay_port if singbox_plan and singbox_plan.xray_sidecar else 0,
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=(
                runtime_xray.ping_host
                if runtime_xray is not None
                else controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config if singbox_plan is not None else {},
                    session_node,
                )[0]
            ),
            ping_port=(
                runtime_xray.ping_port
                if runtime_xray is not None
                else controller._infer_singbox_ping_target(
                    singbox_plan.singbox_config if singbox_plan is not None else {},
                    session_node,
                )[1]
            ),
        )
        controller.save()
        session_mode = "xray-tun" if tun and controller._active_core == "xray" else controller._active_core
        controller._traffic_history.start_session(session_label, session_mode)
        return True
    finally:
        controller._connecting = False


def disconnect_current(controller: AppController, disable_proxy: bool = True, emit_status: bool = True) -> bool:
    controller._disconnecting = True
    try:
        controller._cleanup_connection_runtime_state(
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=not controller._reconnecting and not controller._auto_switch_transitioning,
        )
        active_tun = controller._active_session.tun_mode if controller._active_session is not None else controller.state.settings.tun_mode
        if emit_status and active_tun:
            controller.status.emit("info", "Остановка VPN...")
        stopped = controller._stop_active_connection_processes(disable_proxy=disable_proxy)
        if stopped:
            controller._active_core = "xray"
            controller._clear_active_session()
        if emit_status:
            if stopped:
                controller._set_connection_status("idle", "Отключено", level="info")
            else:
                controller._set_connection_status("error", "Не удалось корректно остановить подключение", level="error")
        return stopped
    finally:
        controller._disconnecting = False


def reconnect(controller: AppController, reason: str) -> bool:
    if controller._reconnecting:
        return False
    controller._reconnecting = True
    controller._switching = True
    try:
        controller._log(f"[reconnect] {reason}")
        controller._set_connection_status("starting", "Переподключение...", level="info")
        stopped = disconnect_current(controller, disable_proxy=False, emit_status=False)
        if not stopped:
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
            if controller.state.settings.enable_system_proxy:
                controller.proxy.disable(restore_previous=True)
            return False

        ok = connect_selected(controller, allow_during_reconnect=True)
        if not ok and controller.state.settings.enable_system_proxy:
            controller.proxy.disable(restore_previous=True)
        return ok
    finally:
        controller._reconnecting = False
        controller._switching = False
        controller._auto_switch_transitioning = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()


def _is_admin() -> bool:
    if not hasattr(ctypes, "windll"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
