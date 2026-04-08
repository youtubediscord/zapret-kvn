from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import SINGBOX_CLASH_API_PORT
from ..live_metrics_worker import LiveMetricsWorker

if TYPE_CHECKING:
    from ..app_controller import AppController


def start_metrics_worker(controller: AppController) -> None:
    session = controller._active_session
    node = controller.selected_node
    ping_host = session.ping_host if session is not None else (node.server if node else "")
    ping_port = session.ping_port if session is not None else (node.port if node else 0)
    controller._log(f"[metrics] starting worker, active_core={controller._active_core}")

    stop_metrics_worker(controller)
    if controller._active_core == "singbox":
        mode = "singbox"
    elif controller._active_session is not None and controller._active_session.tun_mode:
        mode = "xray-tun"
    else:
        mode = "xray"
    socks_port, http_port = controller.get_effective_proxy_ports()
    inbound_tags = controller._active_session.xray_inbound_tags if controller._active_session else ()
    controller._metrics_worker = LiveMetricsWorker(
        controller.state.settings.xray_path,
        controller._xray_api_port,
        ping_host=ping_host,
        ping_port=ping_port,
        mode=mode,
        clash_api_port=SINGBOX_CLASH_API_PORT,
        socks_port=socks_port,
        http_port=http_port,
        xray_inbound_tags=list(inbound_tags),
    )
    controller._metrics_worker.metrics.connect(controller._on_live_metrics)
    controller._metrics_worker.start()


def stop_metrics_worker(controller: AppController) -> None:
    if not controller._metrics_worker:
        return
    if controller._metrics_worker.isRunning():
        controller._metrics_worker.stop()
        controller._metrics_worker.wait(1200)
    controller._metrics_worker = None


def cleanup_connection_runtime_state(
    controller: AppController,
    *,
    end_traffic_session: bool,
    reset_auto_switch_cycle: bool,
    reset_auto_switch_cooldown: bool,
) -> None:
    controller._xray_tun_routes.cleanup()
    controller._xray_api_port = 0
    controller._protect_ss_port = 0
    controller._protect_ss_password = ""
    controller._tun2socks_proxy_username = ""
    controller._tun2socks_proxy_password = ""
    controller._traffic_save_counter = 0
    controller._reset_auto_switch_state(
        reset_cooldown=reset_auto_switch_cooldown,
        reset_cycle=reset_auto_switch_cycle,
    )
    if end_traffic_session:
        controller._traffic_history.end_session()
    from ..process_traffic_collector import reset_connection_tracking
    from ..win_proc_monitor import clear_pid_cache
    reset_connection_tracking()
    clear_pid_cache()


def stop_active_connection_processes(controller: AppController, *, disable_proxy: bool) -> bool:
    stopped = True

    if controller._active_core == "singbox":
        if controller.singbox.is_running:
            stopped = controller.singbox.stop() and stopped
        if controller.xray.is_running:
            stopped = controller.xray.stop() and stopped
        if controller.tun2socks.is_running:
            stopped = controller.tun2socks.stop() and stopped
    elif controller._active_core == "tun2socks":
        if controller.tun2socks.is_running:
            stopped = controller.tun2socks.stop() and stopped
        if controller.xray.is_running:
            stopped = controller.xray.stop() and stopped
        if controller.singbox.is_running:
            stopped = controller.singbox.stop() and stopped
    else:
        if controller.xray.is_running:
            stopped = controller.xray.stop() and stopped
        if controller.singbox.is_running:
            stopped = controller.singbox.stop() and stopped
        if controller.tun2socks.is_running:
            stopped = controller.tun2socks.stop() and stopped

    if disable_proxy and controller.state.settings.enable_system_proxy:
        controller.proxy.disable(restore_previous=True)

    return stopped


def handle_unexpected_disconnect(controller: AppController) -> None:
    if controller._cleaning_connection_state:
        return
    controller._cleaning_connection_state = True
    try:
        cleanup_connection_runtime_state(
            controller,
            end_traffic_session=True,
            reset_auto_switch_cycle=not controller._auto_switch_transitioning,
            reset_auto_switch_cooldown=True,
        )
        stop_active_connection_processes(controller, disable_proxy=not controller._reconnecting)
        controller._active_core = "xray"
        controller._clear_active_session()
        if not controller._reconnecting:
            controller._desired_connected = False
    finally:
        controller._auto_switch_transitioning = False
        controller._cleaning_connection_state = False


def on_core_state_changed(controller: AppController, _running: bool) -> None:
    was_connected, is_connected = controller._refresh_connected_state()
    if not controller._switching and was_connected != is_connected:
        controller.connection_changed.emit(is_connected)
    if is_connected and not controller._switching and not was_connected:
        start_metrics_worker(controller)
    elif not is_connected:
        stop_metrics_worker(controller)
        if was_connected and not controller._switching:
            controller.live_metrics_updated.emit({"down_bps": 0.0, "up_bps": 0.0, "latency_ms": None})
            if not controller._disconnecting:
                handle_unexpected_disconnect(controller)
    if (
        not is_connected
        and controller._active_core == "xray"
        and controller.state.settings.enable_system_proxy
        and not controller._reconnecting
    ):
        controller.proxy.disable(restore_previous=True)


def on_live_metrics(controller: AppController, payload: dict[str, object]) -> None:
    controller.live_metrics_updated.emit(payload)
    down_bps = float(payload.get("down_bps") or 0.0)
    controller._check_auto_switch(down_bps)
    process_stats = payload.get("process_stats")
    if process_stats:
        stats_dict = {}
        for ps in process_stats:
            stats_dict[ps.exe] = (ps.upload, ps.download, ps.route)
        controller._traffic_history.update_session(stats_dict)
        controller._traffic_save_counter += 1
        if controller._traffic_save_counter >= 15:
            controller._traffic_history.save_periodic()
            controller._traffic_save_counter = 0


def shutdown(controller: AppController) -> None:
    if controller._country_resolver and controller._country_resolver.isRunning():
        controller._country_resolver.quit()
        controller._country_resolver.wait(2000)
    if controller._ping_worker and controller._ping_worker.isRunning():
        controller._ping_worker.cancel()
        controller._ping_worker.wait(500)
    if controller._connectivity_worker and controller._connectivity_worker.isRunning():
        controller._connectivity_worker.wait(1000)
    stop_metrics_worker(controller)
    if controller._speed_worker and controller._speed_worker.isRunning():
        controller._speed_worker.cancel()
        controller._speed_worker.wait(20000)
    if controller._xray_update_worker and controller._xray_update_worker.isRunning():
        controller._xray_update_worker.wait(1000)

    controller.disconnect_current()
    if controller.tun2socks.is_running:
        controller.tun2socks.stop()
    if controller.singbox.is_running:
        controller.singbox.stop()
    if controller.xray.is_running:
        controller.xray.stop()
    controller._xray_tun_routes.cleanup()
    if controller.zapret.running:
        controller.zapret.stop()
    if controller.proxy.is_enabled():
        controller.proxy.disable(restore_previous=True)
    controller._cleanup_tun_adapter()
    controller.network_monitor.stop()
    controller._lock_timer.stop()
    controller.save()
