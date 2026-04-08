from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .runtime_planner import SingboxRuntimePlan

if TYPE_CHECKING:
    from ...app_controller import AppController
    from ...models import Node


@dataclass(slots=True)
class SingboxStartResult:
    plan: SingboxRuntimePlan
    session_label: str


def start_tun(
    controller: AppController,
    node: Node | None,
    *,
    prev_active_core: str,
) -> SingboxStartResult | None:
    controller._active_core = "singbox"
    try:
        plan = controller._plan_runtime_singbox(node)
    except ValueError as exc:
        controller._active_core = prev_active_core
        controller._set_connection_status("error", str(exc), level="error")
        return None

    session_label = plan.source_path.name
    if plan.used_selected_node and node is not None:
        session_label = f"{plan.source_path.name} / {node.name}"
    start_message = (
        f"Запуск VPN: {session_label} (sing-box + xray sidecar)..."
        if plan.is_hybrid
        else f"Запуск VPN: {session_label}..."
    )
    controller._set_connection_status("starting", start_message, level="info")
    controller._log(f"[tun] sing-box planner outcome: {plan.outcome} from {plan.source_path}")
    if plan.used_selected_node and node is not None:
        if plan.is_hybrid:
            controller._log(
                f"[tun] outbound tag 'proxy' replaced with local xray relay for unsupported node: {node.name}"
            )
        else:
            controller._log(f"[tun] outbound tag 'proxy' replaced from selected node: {node.name}")

    if not controller._start_singbox_runtime_plan(plan):
        controller._set_connection_status(
            "error",
            (
                "Не удалось запустить sing-box hybrid runtime. Смотрите причину в последних строках лога sing-box."
                if plan.is_hybrid
                else "Не удалось запустить sing-box TUN runtime. Смотрите причину в последних строках лога sing-box."
            ),
            level="error",
        )
        controller._active_core = prev_active_core
        return None

    return SingboxStartResult(plan=plan, session_label=session_label)


def restart_runtime(controller: AppController, reason: str) -> bool:
    node = controller.selected_node
    controller._switching = True
    try:
        controller._log(f"[tun-hot-swap] {reason}")
        try:
            plan = controller._plan_runtime_singbox(node)
        except ValueError as exc:
            controller._set_connection_status("error", str(exc), level="error")
            return False

        session_label = plan.source_path.name
        if plan.used_selected_node and node is not None:
            session_label = f"{plan.source_path.name} / {node.name}"
        start_message = (
            f"Переключение на {session_label} (sing-box + xray sidecar)..."
            if plan.is_hybrid
            else f"Переключение на {session_label}..."
        )
        controller._set_connection_status("starting", start_message, level="info")
        controller._stop_metrics_worker()

        if controller.singbox.is_running and not controller.singbox.stop():
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс sing-box", level="error")
            return False
        if controller.xray.is_running and not controller.xray.stop():
            controller._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray sidecar", level="error")
            return False

        controller._xray_api_port = 0
        controller._protect_ss_port = 0
        controller._protect_ss_password = ""
        if not controller._start_singbox_runtime_plan(plan):
            controller._set_connection_status(
                "error",
                (
                    "Не удалось перезапустить sing-box hybrid runtime. Смотрите причину в последних строках лога sing-box."
                    if plan.is_hybrid
                    else "Не удалось перезапустить sing-box runtime. Смотрите причину в последних строках лога sing-box."
                ),
                level="error",
            )
            controller._handle_unexpected_disconnect()
            return False

        session_node = node if plan.used_selected_node else None
        if session_node is not None:
            session_node.last_used_at = datetime.now(timezone.utc).isoformat()

        ping_host, ping_port = controller._infer_singbox_ping_target(plan.singbox_config, session_node)
        controller._capture_active_session(
            session_node,
            tun=True,
            core="singbox",
            api_port=0,
            hybrid=plan.is_hybrid,
            xray_inbound_tags=(),
            sidecar_relay_port=plan.xray_sidecar.relay_port if plan.xray_sidecar else 0,
            protect_ss_port=controller._protect_ss_port,
            protect_ss_password=controller._protect_ss_password,
            ping_host=ping_host,
            ping_port=ping_port,
        )
        controller._set_connection_status(
            "running",
            f"Переключено: {session_label}" + (" (TUN, xray sidecar)" if plan.is_hybrid else " (TUN)"),
            level="success",
        )
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
