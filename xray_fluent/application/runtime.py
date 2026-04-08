"""Runtime/session/transition facade."""

from .connection_service import connect_selected, disconnect_current, reconnect
from .runtime_services import (
    cleanup_connection_runtime_state,
    handle_unexpected_disconnect,
    on_core_state_changed,
    on_live_metrics,
    shutdown,
    start_metrics_worker,
    stop_active_connection_processes,
    stop_metrics_worker,
)
from .session_state import ActiveSessionSnapshot, XrayRuntimeConfig, build_active_session_snapshot
from .signature_service import (
    routing_signature,
    signature,
    system_proxy_bypass_lan,
    transition_signature,
    tun_layer_signature,
    xray_layer_signature,
)
from .transition_engine import (
    TransitionContext,
    can_apply_proxy_runtime_change,
    can_proxy_hot_swap,
    can_tun_hot_swap,
    compute_transition_action,
    needs_transition,
    transition_status_text,
)
from .update_service import on_xray_update_worker_done, run_xray_core_update
from .worker_service import (
    cancel_speed_test,
    on_connectivity_result,
    on_ping_complete,
    on_ping_progress,
    on_ping_result,
    on_speed_complete,
    on_speed_node_progress,
    on_speed_progress,
    on_speed_result,
    ping_nodes,
    speed_test_nodes,
    test_connectivity,
)
