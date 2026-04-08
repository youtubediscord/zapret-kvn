from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..connectivity_test import ConnectivityTestWorker
from ..constants import DEFAULT_HTTP_PORT, XRAY_PATH_DEFAULT
from ..path_utils import resolve_configured_path
from ..ping_worker import PingWorker
from ..speed_test_worker import SpeedTestWorker

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


def ping_nodes(controller: AppController, node_ids: set[str] | None = None) -> None:
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if not nodes:
        return

    if controller._ping_worker and controller._ping_worker.isRunning():
        controller._ping_worker.cancel()
        controller._ping_worker.wait(500)

    controller._ping_total = len(nodes)
    controller._ping_completed = 0
    controller.bulk_task_progress.emit("ping", 0, controller._ping_total, False)
    controller._ping_worker = PingWorker(nodes)
    controller._ping_worker.result.connect(controller._on_ping_result)
    controller._ping_worker.progress.connect(controller._on_ping_progress)
    controller._ping_worker.completed.connect(controller._on_ping_complete)
    controller._ping_worker.start()


def speed_test_nodes(controller: AppController, node_ids: set[str] | None = None) -> bool:
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if not nodes:
        return False

    if controller._speed_worker and controller._speed_worker.isRunning():
        controller.status.emit("info", "Тест скорости уже выполняется. Остановите его перед новым запуском.")
        return False

    resolved = resolve_configured_path(
        controller.state.settings.xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    xray_path = str(resolved) if resolved else controller.state.settings.xray_path

    controller._speed_total = len(nodes)
    controller._speed_completed = 0
    controller.bulk_task_progress.emit("speed", 0, controller._speed_total, False)
    controller._speed_worker = SpeedTestWorker(
        nodes,
        xray_path=xray_path,
        routing=controller.state.routing,
    )
    controller._speed_worker.result.connect(controller._on_speed_result)
    controller._speed_worker.progress.connect(controller._on_speed_progress)
    controller._speed_worker.node_progress.connect(controller._on_speed_node_progress)
    controller._speed_worker.completed.connect(controller._on_speed_complete)
    controller._speed_worker.start()
    return True


def cancel_speed_test(controller: AppController) -> bool:
    worker = controller._speed_worker
    if worker is None or not worker.isRunning():
        controller.status.emit("info", "Тест скорости сейчас не выполняется")
        return False
    worker.cancel()
    controller.status.emit("info", "Останавливаю тест скорости...")
    return True


def test_connectivity(controller: AppController, url: str | None = None) -> None:
    target = (url or "https://www.gstatic.com/generate_204").strip()
    if not target:
        target = "https://www.gstatic.com/generate_204"

    if controller._connectivity_worker and controller._connectivity_worker.isRunning():
        controller.status.emit("info", "Тест подключения уже выполняется")
        return

    http_port = controller.get_effective_http_proxy_port() or DEFAULT_HTTP_PORT
    controller._connectivity_worker = ConnectivityTestWorker(http_port, target, tun_mode=controller.state.settings.tun_mode)
    controller._connectivity_worker.result.connect(controller._on_connectivity_result)
    controller._connectivity_worker.start()


def on_ping_result(controller: AppController, node_id: str, ping_ms: int | None) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    for node in controller.state.nodes:
        if node.id == node_id:
            node.ping_ms = ping_ms
            if ping_ms is not None or node.is_alive is None:
                node.is_alive = ping_ms is not None
            ts = datetime.now(timezone.utc).isoformat()
            node.ping_history.append((ts, ping_ms))
            if len(node.ping_history) > 50:
                node.ping_history = node.ping_history[-50:]
            break
    controller.ping_updated.emit(node_id, ping_ms)


def on_ping_progress(controller: AppController, current: int, total: int) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    controller._ping_completed = current
    controller.bulk_task_progress.emit("ping", current, total, False)


def on_ping_complete(controller: AppController) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    controller.bulk_task_progress.emit("ping", controller._ping_completed, controller._ping_total, True)
    controller._ping_worker = None
    controller.save()


def on_speed_result(controller: AppController, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    for node in controller.state.nodes:
        if node.id == node_id:
            node.speed_mbps = speed_mbps
            if is_alive or node.is_alive is None:
                node.is_alive = is_alive
            ts = datetime.now(timezone.utc).isoformat()
            node.speed_history.append((ts, speed_mbps))
            if len(node.speed_history) > 50:
                node.speed_history = node.speed_history[-50:]
            break
    controller.save()
    controller.speed_updated.emit(node_id, speed_mbps, is_alive)


def on_speed_progress(controller: AppController, current: int, total: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller._speed_completed = current
    controller.bulk_task_progress.emit("speed", current, total, False)


def on_speed_node_progress(controller: AppController, node_id: str, percent: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller.speed_progress_updated.emit(node_id, max(0, min(100, int(percent))))


def on_speed_complete(controller: AppController) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    worker = controller._speed_worker
    cancelled = bool(worker.was_cancelled) if worker is not None else False
    completed = worker.completed_nodes if worker is not None else controller._speed_completed
    controller._speed_completed = completed
    if cancelled:
        controller.speed_test_cancelled.emit(completed, controller._speed_total)
    controller.bulk_task_progress.emit("speed", completed, controller._speed_total, True)
    controller._speed_worker = None
    if cancelled:
        controller.status.emit("info", f"Тест скорости остановлен ({completed}/{controller._speed_total})")
    else:
        controller.status.emit("success", "Тест скорости завершён")


def on_connectivity_result(controller: AppController, ok: bool, message: str, elapsed_ms: int | None) -> None:
    if controller.sender() is not controller._connectivity_worker:
        return
    controller._connectivity_worker = None
    if ok and elapsed_ms is not None:
        text = f"Подключение в порядке: {elapsed_ms} мс"
        controller.status.emit("success", text)
        controller._log(f"[test] {message} ({elapsed_ms} ms)")
    else:
        controller.status.emit("warning", "Тест подключения не пройден")
        controller._log(f"[test] {message}")
    controller.connectivity_test_done.emit(ok, message, elapsed_ms)
