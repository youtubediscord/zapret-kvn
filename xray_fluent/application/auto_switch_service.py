from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10
AUTO_SWITCH_IDLE_BPS = 1024.0


def check_auto_switch(controller: AppController, down_bps: float) -> None:
    settings = controller.state.settings
    if not settings.auto_switch_enabled:
        return
    if not controller.connected or controller._switching or controller._reconnecting:
        return
    if len(controller.state.nodes) < 2:
        return
    if controller._auto_switch_exhausted:
        return

    now = time.monotonic()
    threshold_bps = settings.auto_switch_threshold_kbps * 1024.0

    if down_bps >= threshold_bps:
        controller._auto_switch_high_ticks += 1
        if controller._auto_switch_high_ticks >= AUTO_SWITCH_HIGH_TICKS_REQUIRED:
            controller._auto_switch_active_download = True
        controller._auto_switch_low_since = 0.0
        return

    if not controller._auto_switch_active_download:
        controller._auto_switch_high_ticks = 0
        return

    if down_bps < AUTO_SWITCH_IDLE_BPS:
        controller._auto_switch_low_since = 0.0
        controller._auto_switch_high_ticks = 0
        controller._auto_switch_active_download = False
        return

    controller._auto_switch_high_ticks = 0

    if controller._auto_switch_low_since == 0.0:
        controller._auto_switch_low_since = now
        return

    low_duration = now - controller._auto_switch_low_since
    if low_duration < settings.auto_switch_delay_sec:
        return

    if now - controller._auto_switch_last_switch < settings.auto_switch_cooldown_sec:
        return

    max_attempts = max(1, len(controller.state.nodes) - 1)
    if controller._auto_switch_cycle_attempts >= max_attempts:
        controller._auto_switch_exhausted = True
        controller._auto_switch_low_since = 0.0
        controller._auto_switch_active_download = False
        controller.status.emit("warning", "Автопереключение остановлено: все серверы уже проверены")
        controller._log("[auto-switch] exhausted all nodes for current session")
        return

    controller._auto_switch_low_since = 0.0
    controller._auto_switch_last_switch = now
    controller._auto_switch_active_download = False

    next_node = get_next_node_for_auto_switch(controller)
    if not next_node:
        return

    controller._auto_switch_cycle_attempts += 1
    controller._auto_switch_transitioning = True
    controller._log(
        f"[auto-switch] speed {down_bps / 1024:.0f} KB/s < {settings.auto_switch_threshold_kbps} KB/s "
        f"for {low_duration:.0f}s → switching to {next_node.name}"
    )
    controller.auto_switch_triggered.emit(next_node.name)

    controller.state.selected_node_id = next_node.id
    controller.selection_changed.emit(next_node)
    controller.save()
    controller._desired_connected = True
    controller._request_transition("auto-switch: speed drop")


def get_next_node_for_auto_switch(controller: AppController) -> Node | None:
    current_id = controller.state.selected_node_id
    nodes = controller.state.nodes
    if not nodes:
        return None

    candidates = [
        node
        for node in nodes
        if node.id != current_id and node.is_alive is True and node.speed_mbps is not None and node.speed_mbps > 0
    ]
    if candidates:
        return max(candidates, key=lambda node: node.speed_mbps)

    candidates = [node for node in nodes if node.id != current_id and node.is_alive is True]
    if candidates:
        return min(candidates, key=lambda node: node.ping_ms if node.ping_ms is not None else float("inf"))

    current_idx: int | None = None
    for idx, node in enumerate(nodes):
        if node.id == current_id:
            current_idx = idx
            break
    if current_idx is None:
        return nodes[0]
    next_idx = (current_idx + 1) % len(nodes)
    if nodes[next_idx].id == current_id:
        return None
    return nodes[next_idx]
