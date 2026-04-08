from __future__ import annotations

from typing import TYPE_CHECKING

from ..engines.xray import XrayCoreUpdateResult, XrayCoreUpdateWorker

if TYPE_CHECKING:
    from ..app_controller import AppController


def run_xray_core_update(controller: AppController, apply_update: bool, silent: bool = False) -> None:
    if controller._xray_update_worker and controller._xray_update_worker.isRunning():
        if not silent:
            controller.status.emit("info", "Обновление Xray уже выполняется")
        return

    if silent and apply_update and controller.connected:
        controller._log("[core-update] silent auto-update skipped while connected")
        return

    if apply_update and controller.connected:
        stopped = controller.disconnect_current()
        if not stopped:
            controller._reconnect_after_xray_update = False
            if silent:
                controller._log("[core-update] update cancelled: failed to stop active connection")
            else:
                controller.status.emit("error", "Не удалось остановить активное подключение перед обновлением Xray")
            return
        controller._reconnect_after_xray_update = True
    else:
        controller._reconnect_after_xray_update = False

    controller._xray_update_silent = silent
    controller._xray_update_worker = XrayCoreUpdateWorker(
        controller.state.settings.xray_path,
        controller.state.settings.xray_release_channel,
        controller.state.settings.xray_update_feed_url,
        apply_update=apply_update,
    )
    controller._xray_update_worker.done.connect(controller._on_xray_update_worker_done)
    controller._xray_update_worker.start()

    if not silent:
        message = "Обновление Xray..." if apply_update else "Проверка обновлений Xray..."
        controller.status.emit("info", message)


def on_xray_update_worker_done(controller: AppController, result: XrayCoreUpdateResult) -> None:
    controller._xray_update_worker = None
    controller.xray_update_result.emit(result)

    if result.status == "error":
        if not controller._xray_update_silent:
            controller.status.emit("error", result.message)
        else:
            controller._log(f"[core-update] error: {result.message}")
    elif result.status == "updated":
        if not controller._xray_update_silent:
            controller.status.emit("success", result.message)
        controller._log(f"[core-update] {result.message}")
    elif result.status == "available":
        if not controller._xray_update_silent:
            controller.status.emit("warning", result.message)
        else:
            controller._log(f"[core-update] {result.message}")
    elif result.status == "up_to_date":
        if not controller._xray_update_silent:
            controller.status.emit("info", result.message)
        else:
            controller._log(f"[core-update] {result.message}")

    if controller._reconnect_after_xray_update:
        controller._reconnect_after_xray_update = False
        controller._desired_connected = True
        controller._request_transition("core update reconnect")

    controller._xray_update_silent = False
