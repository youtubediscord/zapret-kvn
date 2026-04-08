from __future__ import annotations

from copy import deepcopy
import hashlib
import logging
import socket
from datetime import datetime, timezone
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .application.config import (
    SingboxDocumentCache,
    apply_singbox_config_text as apply_singbox_config_text_operation,
    apply_xray_config_text as apply_xray_config_text_operation,
    apply_xray_tun_loop_prevention as apply_xray_tun_loop_prevention_operation,
    build_runtime_xray_config as build_runtime_xray_config_operation,
    collect_xray_inbound_ports,
    config_has_proxy_outbound,
    default_singbox_config_text,
    default_xray_config_text,
    ensure_active_config as ensure_active_config_operation,
    ensure_dict,
    ensure_list,
    ensure_xray_metrics_contract as ensure_xray_metrics_contract_operation,
    ensure_xray_tun_contract as ensure_xray_tun_contract_operation,
    extract_xray_runtime_ports,
    format_json_error_message,
    get_active_config_name as get_active_config_name_operation,
    get_active_config_path as get_active_config_path_operation,
    get_active_template_path as get_active_template_path_operation,
    import_template as import_template_operation,
    infer_singbox_outbound_endpoint,
    infer_singbox_ping_target,
    infer_xray_outbound_endpoint,
    infer_xray_ping_target,
    inspect_active_xray_config as inspect_active_xray_config_operation,
    is_local_runtime_host,
    load_active_config_text as load_active_config_text_operation,
    load_config_text as load_config_text_operation,
    normalize_relative_json_path,
    replace_or_append_tagged,
    reset_active_config_to_template as reset_active_config_to_template_operation,
    resolve_profile_path,
    save_config_text as save_config_text_operation,
    validate_json_text,
    xray_outbound_is_loop_protected as xray_outbound_is_loop_protected_operation,
)
from .application.nodes import (
    bulk_update_nodes as bulk_update_nodes_operation,
    check_auto_switch as check_auto_switch_operation,
    detect_countries_sync as detect_countries_sync_operation,
    get_all_groups as get_all_groups_operation,
    get_all_tags as get_all_tags_operation,
    get_fastest_alive_node as get_fastest_alive_node_operation,
    get_next_node_for_auto_switch as get_next_node_for_auto_switch_operation,
    get_node_by_id as get_node_by_id_operation,
    import_nodes_from_text as import_nodes_from_text_operation,
    on_countries_resolved as on_countries_resolved_operation,
    prepare_node_for_runtime as prepare_node_for_runtime_operation,
    remove_nodes as remove_nodes_operation,
    reorder_nodes as reorder_nodes_operation,
    set_selected_node as set_selected_node_operation,
    start_country_ip_resolution as start_country_ip_resolution_operation,
    update_node as update_node_operation,
)
from .application.runtime import (
    ActiveSessionSnapshot,
    TransitionContext,
    XrayRuntimeConfig,
    build_active_session_snapshot,
    can_apply_proxy_runtime_change as can_apply_proxy_runtime_change_rule,
    can_proxy_hot_swap as can_proxy_hot_swap_rule,
    can_tun_hot_swap as can_tun_hot_swap_rule,
    cancel_speed_test as cancel_speed_test_operation,
    cleanup_connection_runtime_state as cleanup_connection_runtime_state_operation,
    compute_transition_action,
    connect_selected as connect_selected_operation,
    disconnect_current as disconnect_current_operation,
    handle_unexpected_disconnect as handle_unexpected_disconnect_operation,
    needs_transition,
    on_connectivity_result as on_connectivity_result_operation,
    on_core_state_changed as on_core_state_changed_operation,
    on_live_metrics as on_live_metrics_operation,
    on_ping_complete as on_ping_complete_operation,
    on_ping_progress as on_ping_progress_operation,
    on_ping_result as on_ping_result_operation,
    on_speed_complete as on_speed_complete_operation,
    on_speed_node_progress as on_speed_node_progress_operation,
    on_speed_progress as on_speed_progress_operation,
    on_speed_result as on_speed_result_operation,
    on_xray_update_worker_done as on_xray_update_worker_done_operation,
    ping_nodes as ping_nodes_operation,
    reconnect as reconnect_operation,
    routing_signature as routing_signature_operation,
    run_xray_core_update as run_xray_core_update_operation,
    shutdown as shutdown_operation,
    signature as signature_operation,
    speed_test_nodes as speed_test_nodes_operation,
    start_metrics_worker as start_metrics_worker_operation,
    stop_active_connection_processes as stop_active_connection_processes_operation,
    stop_metrics_worker as stop_metrics_worker_operation,
    system_proxy_bypass_lan as system_proxy_bypass_lan_operation,
    test_connectivity as test_connectivity_operation,
    transition_signature as transition_signature_operation,
    transition_status_text,
    tun_layer_signature as tun_layer_signature_operation,
    xray_layer_signature as xray_layer_signature_operation,
)
from .country_flags import CountryResolver
from .engines.xray import (
    XrayManager,
    XrayTunRouteManager,
    build_xray_config,
    get_windows_default_route_context,
    get_xray_version,
    restart_proxy_core as restart_xray_proxy_core,
)
from .engines.singbox import (
    SingBoxManager,
    classify_node_for_singbox,
    get_singbox_version,
    parse_singbox_document,
    plan_singbox_runtime,
    restart_runtime as restart_singbox_runtime_operation,
    SingboxDocumentState,
    SingboxRuntimePlan,
)
from .constants import (
    APP_NAME,
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    DEFAULT_XRAY_STATS_API_PORT,
    LOG_DIR,
    PROXY_HOST,
    ROUTING_MODES,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_CONFIGS_DIR,
    SINGBOX_DEFAULT_CONFIG_NAME,
    SINGBOX_TEMPLATES_DIR,
    XRAY_CONFIGS_DIR,
    XRAY_DEFAULT_CONFIG_NAME,
    XRAY_TUN_DEFAULT_INTERFACE_NAME,
    XRAY_TEMPLATES_DIR,
)
from .diagnostics import export_diagnostics
from .models import AppSettings, AppState, Node, RoutingSettings
from .network_monitor import NetworkMonitor
from .proxy_manager import ProxyManager
from .security import create_password_hash, get_idle_seconds, verify_password
from .engines.tun2socks import Tun2SocksManager, hot_swap as hot_swap_tun2socks
from .storage import PassphraseRequired, StateStorage
from .startup import build_startup_command, set_startup_enabled
from .subprocess_utils import result_output_text, run_text
from .traffic_history import TrafficHistoryStorage
from .zapret_manager import ZapretManager

if TYPE_CHECKING:
    from .country_flags import CountryResolver as CountryResolverType
    from .connectivity_test import ConnectivityTestWorker
    from .engines.xray import XrayCoreUpdateResult, XrayCoreUpdateWorker
    from .live_metrics_worker import LiveMetricsWorker
    from .ping_worker import PingWorker
    from .speed_test_worker import SpeedTestWorker


def _find_free_api_port(preferred: int | None = None, excluded: set[int] | None = None) -> int:
    """Find a free TCP port near *preferred* for the xray stats API."""
    if preferred is None:
        preferred = DEFAULT_XRAY_STATS_API_PORT
    for port in range(preferred, preferred + 100):
        if excluded and port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {preferred}-{preferred + 100}")


_XRAY_METRICS_API_TAG = "__app_metrics_api"
_XRAY_METRICS_API_INBOUND_TAG = "__app_metrics_api_in"
_XRAY_TUN_INBOUND_TAG = "__app_tun_in"
class AppController(QObject):
    nodes_changed = pyqtSignal(object)
    selection_changed = pyqtSignal(object)
    connection_changed = pyqtSignal(bool)
    connection_status_changed = pyqtSignal(str, str)
    routing_changed = pyqtSignal(object)
    settings_changed = pyqtSignal(object)
    log_line = pyqtSignal(str)
    status = pyqtSignal(str, str)
    bulk_task_progress = pyqtSignal(str, int, int, bool)  # task, current, total, completed
    ping_updated = pyqtSignal(str, object)
    speed_updated = pyqtSignal(str, object, bool)  # node_id, speed_mbps, is_alive
    speed_progress_updated = pyqtSignal(str, int)  # node_id, percent
    speed_test_cancelled = pyqtSignal(int, int)  # completed, total
    connectivity_test_done = pyqtSignal(bool, str, object)
    live_metrics_updated = pyqtSignal(object)
    xray_update_result = pyqtSignal(object)
    lock_state_changed = pyqtSignal(bool)
    passphrase_required = pyqtSignal()
    auto_switch_triggered = pyqtSignal(str)  # node name we're switching to
    transition_state_changed = pyqtSignal(bool, str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self.storage = StateStorage()
        self.xray = XrayManager(self)
        self.singbox = SingBoxManager(self)
        self.tun2socks = Tun2SocksManager(self)
        self._xray_tun_routes = XrayTunRouteManager(self)
        self.zapret = ZapretManager(self)
        self.proxy = ProxyManager()
        self.network_monitor = NetworkMonitor(parent=self)

        self.state = AppState()
        self.recent_logs: list[str] = []
        self.connected = False
        self.locked = False

        # --- File logger (5 MB × 3 rotated files in data/logs/) ---
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("xray_fluent")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                LOG_DIR / "app.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
            self._logger.addHandler(handler)

        self._country_resolver: CountryResolver | None = None
        self._ping_worker: PingWorker | None = None
        self._speed_worker: SpeedTestWorker | None = None
        self._connectivity_worker: ConnectivityTestWorker | None = None
        self._metrics_worker: LiveMetricsWorker | None = None
        self._xray_update_worker: XrayCoreUpdateWorker | None = None
        self._singbox_documents = SingboxDocumentCache()
        self._ping_total = 0
        self._ping_completed = 0
        self._speed_total = 0
        self._speed_completed = 0
        self._xray_update_silent = False
        self._reconnect_after_xray_update = False
        self._reconnecting = False
        self._connecting = False
        self._disconnecting = False
        self._cleaning_connection_state = False
        self._switching = False  # suppress intermediate UI updates during stop→start
        self._active_core: str = "xray"  # "xray" | "singbox" | "tun2socks"
        self._protect_ss_port: int = 0
        self._protect_ss_password: str = ""
        self._tun2socks_proxy_username: str = ""
        self._tun2socks_proxy_password: str = ""
        self._xray_api_port: int = 0
        self._traffic_history = TrafficHistoryStorage()
        self._traffic_save_counter = 0

        # --- Auto-switch state ---
        self._auto_switch_low_since: float = 0.0  # monotonic timestamp when speed first dropped
        self._auto_switch_last_switch: float = 0.0  # monotonic timestamp of last auto-switch
        self._auto_switch_high_ticks: int = 0  # consecutive readings above threshold
        self._auto_switch_active_download: bool = False  # True after sustained traffic
        self._auto_switch_cycle_attempts: int = 0
        self._auto_switch_exhausted: bool = False
        self._auto_switch_transitioning: bool = False
        self._active_session: ActiveSessionSnapshot | None = None
        self._desired_connected = False
        self._transition_active = False
        self._transition_scheduled = False
        self._transition_pending = False
        self._transition_reason = ""
        self._transition_generation = 0
        self._blocked_transition_signature = ""

        self.xray.log_received.connect(self._on_xray_log)
        self.xray.error.connect(self._on_xray_error)
        self.xray.state_changed.connect(self._on_core_state_changed)
        self.xray.stopped.connect(lambda code: self._on_core_stopped("xray", code))

        self.singbox.log_received.connect(self._on_xray_log)
        self.singbox.error.connect(self._on_singbox_error)
        self.singbox.state_changed.connect(self._on_core_state_changed)
        self.singbox.stopped.connect(lambda code: self._on_core_stopped("singbox", code))

        self.tun2socks.log_received.connect(self._on_xray_log)
        self.tun2socks.error.connect(self._on_singbox_error)
        self.tun2socks.state_changed.connect(self._on_core_state_changed)
        self.tun2socks.stopped.connect(lambda code: self._on_core_stopped("tun2socks", code))
        self._xray_tun_routes.log_received.connect(self._on_xray_log)

        self.network_monitor.network_changed.connect(self._on_network_changed)

        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(15_000)
        self._lock_timer.timeout.connect(self._check_auto_lock)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(250)
        self._save_timer.timeout.connect(self._flush_scheduled_save)
        self._save_pending = False

    def load(self) -> bool:
        try:
            self.state = self.storage.load()
        except PassphraseRequired:
            self.passphrase_required.emit()
            return False

        self._detect_countries_sync()
        self._migrate_sort_order()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)
        QTimer.singleShot(500, self._start_country_ip_resolution)

        version = get_xray_version(self.state.settings.xray_path)
        if version:
            self._log(f"[core] {version}")
        else:
            self.status.emit("warning", "Не удалось прочитать версию Xray")

        sb_version = get_singbox_version(self.state.settings.singbox_path)
        if sb_version:
            self._log(f"[core] sing-box: {sb_version}")

        self.network_monitor.start()
        self._lock_timer.start()
        return True

    def set_data_passphrase(self, passphrase: str) -> None:
        self.storage.passphrase = passphrase
        self.save()
        self.status.emit("success", "Шифрование данных включено")

    def clear_data_passphrase(self) -> None:
        self.storage.passphrase = ""
        self.save()
        self.status.emit("info", "Шифрование данных отключено (портативный режим)")

    def is_data_encrypted(self) -> bool:
        return self.storage.is_encrypted()

    def save(self) -> None:
        if self._save_timer.isActive():
            self._save_timer.stop()
        self._save_pending = False
        self.storage.save(self.state)

    def schedule_save(self) -> None:
        self._save_pending = True
        self._save_timer.start()

    def _flush_scheduled_save(self) -> None:
        if not self._save_pending:
            return
        self._save_pending = False
        self.storage.save(self.state)

    @staticmethod
    def _signature(payload: object) -> str:
        return signature_operation(payload)

    def _routing_signature(self, routing: RoutingSettings | None = None) -> str:
        return routing_signature_operation(self, routing)

    def is_singbox_editor_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "singbox")

    def is_xray_tun_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "xray")

    def is_tun2socks_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "tun2socks")

    def uses_xray_raw_config(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return not self.is_singbox_editor_mode(settings) and not self.is_tun2socks_mode(settings)

    def _can_connect_without_selected_node(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        if self.is_singbox_editor_mode(settings):
            _, _, has_proxy_outbound = self._inspect_active_singbox_config()
            return not has_proxy_outbound
        if self.uses_xray_raw_config(settings):
            _, _, has_proxy_outbound, _, _, _ = self._inspect_active_xray_config()
            return not has_proxy_outbound
        return False

    def _system_proxy_bypass_lan(self, settings: AppSettings | None = None) -> bool:
        return system_proxy_bypass_lan_operation(self, settings)

    def get_singbox_config_dir(self) -> Path:
        SINGBOX_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_CONFIGS_DIR

    def get_xray_config_dir(self) -> Path:
        XRAY_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_CONFIGS_DIR

    def get_singbox_template_dir(self) -> Path:
        SINGBOX_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return SINGBOX_TEMPLATES_DIR

    def get_xray_template_dir(self) -> Path:
        XRAY_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        return XRAY_TEMPLATES_DIR

    def _normalize_singbox_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, SINGBOX_DEFAULT_CONFIG_NAME)

    def _normalize_singbox_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_singbox_config_relative_path(value)

    def _resolve_singbox_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_config_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box",
        )

    def _resolve_singbox_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.singbox_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_singbox_template_dir(),
            value,
            SINGBOX_DEFAULT_CONFIG_NAME,
            label="sing-box template",
        )

    def _normalize_xray_config_relative_path(self, value: str | Path | None) -> str:
        return normalize_relative_json_path(value, XRAY_DEFAULT_CONFIG_NAME)

    def _normalize_xray_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_xray_config_relative_path(value)

    def _resolve_xray_config_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_config_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_config_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray",
        )

    def _resolve_xray_template_path(self, path: str | Path | None = None) -> Path:
        value = self.state.settings.xray_template_file if path is None or not str(path).strip() else path
        return resolve_profile_path(
            self.get_xray_template_dir(),
            value,
            XRAY_DEFAULT_CONFIG_NAME,
            label="xray template",
        )

    def _set_active_singbox_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_config_path(path)
        relative = resolved.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        if self.state.settings.singbox_config_file == relative:
            return resolved
        self.state.settings.singbox_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_singbox_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_singbox_template_path(path)
        relative = resolved.relative_to(self.get_singbox_template_dir().resolve()).as_posix()
        if self.state.settings.singbox_template_file == relative:
            return resolved
        self.state.settings.singbox_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_config_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_config_path(path)
        relative = resolved.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        if self.state.settings.xray_config_file == relative:
            return resolved
        self.state.settings.xray_config_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    def _set_active_xray_template_path(self, path: Path, *, emit_signal: bool = True) -> Path:
        resolved = self._resolve_xray_template_path(path)
        relative = resolved.relative_to(self.get_xray_template_dir().resolve()).as_posix()
        if self.state.settings.xray_template_file == relative:
            return resolved
        self.state.settings.xray_template_file = relative
        if emit_signal:
            self.settings_changed.emit(self.state.settings)
        self.schedule_save()
        return resolved

    @staticmethod
    def _default_singbox_config_text() -> str:
        return default_singbox_config_text()

    @staticmethod
    def _default_xray_config_text() -> str:
        return default_xray_config_text(
            proxy_host=PROXY_HOST,
            socks_port=DEFAULT_SOCKS_PORT,
            http_port=DEFAULT_HTTP_PORT,
            api_port=DEFAULT_XRAY_STATS_API_PORT,
        )

    def get_active_singbox_config_path(self) -> Path:
        return get_active_config_path_operation(self, "singbox")

    def get_active_singbox_config_name(self) -> str:
        return get_active_config_name_operation(self, "singbox")

    def get_active_singbox_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "singbox")

    def get_active_xray_config_path(self) -> Path:
        return get_active_config_path_operation(self, "xray")

    def get_active_xray_config_name(self) -> str:
        return get_active_config_name_operation(self, "xray")

    def get_active_xray_template_path(self) -> Path | None:
        return get_active_template_path_operation(self, "xray")

    def get_effective_proxy_ports(self) -> tuple[int, int]:
        session = self._active_session
        if session is not None and session.socks_port > 0 and session.http_port > 0:
            return session.socks_port, session.http_port
        try:
            _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        except Exception:
            socks_port = 0
            http_port = 0
        if socks_port > 0 and http_port > 0:
            return socks_port, http_port
        return DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT

    def get_effective_http_proxy_port(self) -> int | None:
        session = self._active_session
        if session is not None and session.tun_mode:
            return None
        _, http_port = self.get_effective_proxy_ports()
        return http_port if http_port > 0 else None

    def _cache_singbox_document_state(self, path: Path, text: str) -> SingboxDocumentState:
        return self._singbox_documents.cache_state(path, text)

    def _get_singbox_document_state(self) -> SingboxDocumentState:
        path = self._ensure_active_singbox_config()
        return self._singbox_documents.get_state(path)

    def _default_singbox_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        template = self._resolve_singbox_template_path(relative)
        return template if template.exists() else None

    def _default_xray_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        template = self._resolve_xray_template_path(relative)
        return template if template.exists() else None

    def _ensure_active_singbox_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "singbox", path)

    def _ensure_active_xray_config(self, path: str | Path | None = None) -> Path:
        return ensure_active_config_operation(self, "xray", path)

    def load_active_singbox_config_text(self) -> tuple[Path, str]:
        return load_active_config_text_operation(self, "singbox")

    def load_active_xray_config_text(self) -> tuple[Path, str]:
        return load_active_config_text_operation(self, "xray")

    def load_singbox_config_text(self, path: str | Path) -> tuple[Path, str]:
        return load_config_text_operation(self, "singbox", path)

    def load_xray_config_text(self, path: str | Path) -> tuple[Path, str]:
        return load_config_text_operation(self, "xray", path)

    def import_singbox_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "singbox", path)

    def import_xray_template(self, path: str | Path) -> tuple[Path, str]:
        return import_template_operation(self, "xray", path)

    def reset_active_singbox_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "singbox")

    def reset_active_xray_config_to_template(self) -> tuple[bool, Path | None, str]:
        return reset_active_config_to_template_operation(self, "xray")

    def save_singbox_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "singbox", text, path)

    def save_xray_config_text(self, text: str, path: str | Path | None = None) -> Path:
        return save_config_text_operation(self, "xray", text, path)

    @staticmethod
    def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
        return format_json_error_message(text, exc)

    def validate_json_text(self, text: str) -> tuple[bool, str]:
        return validate_json_text(text)

    def validate_singbox_json_text(self, text: str) -> tuple[bool, str]:
        return self.validate_json_text(text)

    def validate_xray_json_text(self, text: str) -> tuple[bool, str]:
        ok, message = self.validate_json_text(text)
        if not ok:
            return False, message
        if "fakedns" in text.lower():
            return (
                True,
                "JSON корректен. Внимание: в конфиге есть FakeDNS; некоторые версии Xray-core могут падать на старте. "
                "Если запуск завершается с panic, отключите FakeDNS или обновите Xray core.",
            )
        return True, message

    def apply_singbox_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_singbox_config_text_operation(self, text)

    def apply_xray_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        return apply_xray_config_text_operation(self, text)

    @staticmethod
    def _config_has_proxy_outbound(payload: Any) -> bool:
        return config_has_proxy_outbound(payload)

    @staticmethod
    def _is_local_runtime_host(value: str) -> bool:
        return is_local_runtime_host(value)

    @staticmethod
    def _infer_singbox_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_singbox_outbound_endpoint(outbound)

    @staticmethod
    def _infer_xray_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        return infer_xray_outbound_endpoint(outbound)

    @staticmethod
    def _infer_singbox_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_singbox_ping_target(payload, node)

    @staticmethod
    def _infer_xray_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        return infer_xray_ping_target(payload, node)

    @staticmethod
    def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
        return ensure_dict(parent, key)

    @staticmethod
    def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
        return ensure_list(parent, key)

    @staticmethod
    def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
        replace_or_append_tagged(items, tag, payload)

    @staticmethod
    def _collect_xray_inbound_ports(payload: Any) -> set[int]:
        return collect_xray_inbound_ports(payload)

    def _ensure_xray_metrics_contract(
        self,
        payload: dict[str, Any],
        *,
        allocate_port: bool,
    ) -> tuple[int, tuple[str, ...]]:
        return ensure_xray_metrics_contract_operation(self, payload, allocate_port=allocate_port)

    def _ensure_xray_tun_contract(self, payload: dict[str, Any]) -> str:
        return ensure_xray_tun_contract_operation(self, payload)

    @staticmethod
    def _xray_outbound_is_loop_protected(outbound: dict[str, Any]) -> bool:
        return xray_outbound_is_loop_protected_operation(outbound)

    def _apply_xray_tun_loop_prevention(self, payload: dict[str, Any], interface_alias: str) -> int:
        return apply_xray_tun_loop_prevention_operation(self, payload, interface_alias)

    def _inspect_active_singbox_config(self) -> tuple[Path, str, bool]:
        state = self._get_singbox_document_state()
        return state.source_path, state.text_hash, state.has_proxy_outbound

    @staticmethod
    def _extract_xray_runtime_ports(payload: Any) -> tuple[int, int, int]:
        return extract_xray_runtime_ports(payload)

    def _inspect_active_xray_config(self) -> tuple[Path, str, bool, int, int, int]:
        return inspect_active_xray_config_operation(self)

    def _plan_runtime_singbox(self, node: Node | None = None) -> SingboxRuntimePlan:
        state = self._get_singbox_document_state()
        document = parse_singbox_document(state.source_path, state.text)
        preferred_relay_port = 0
        preferred_protect_port = 0
        preferred_protect_password = ""
        session = self._active_session
        if session is not None and session.active_core == "singbox" and session.hybrid:
            preferred_relay_port = session.sidecar_relay_port
            preferred_protect_port = session.protect_ss_port
            preferred_protect_password = session.protect_ss_password
        return plan_singbox_runtime(
            document,
            node,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
        )

    def _start_singbox_runtime_plan(self, plan: SingboxRuntimePlan) -> bool:
        if plan.xray_sidecar is not None:
            self._protect_ss_port = plan.xray_sidecar.protect_port
            self._protect_ss_password = plan.xray_sidecar.protect_password
            self._log(
                "[tun] starting hybrid xray sidecar "
                f"relay=127.0.0.1:{plan.xray_sidecar.relay_port} "
                f"protect=127.0.0.1:{plan.xray_sidecar.protect_port}"
            )
            if not self.xray.start(self.state.settings.xray_path, plan.xray_sidecar.config):
                self._protect_ss_port = 0
                self._protect_ss_password = ""
                return False
        else:
            self._protect_ss_port = 0
            self._protect_ss_password = ""

        sb_ok = self.singbox.start(self.state.settings.singbox_path, plan.singbox_config)
        self._log(f"[tun] sing-box start result: {sb_ok}")
        if sb_ok:
            return True

        if plan.xray_sidecar is not None and self.xray.is_running:
            self.xray.stop()
        self._protect_ss_port = 0
        self._protect_ss_password = ""
        return False

    def _build_runtime_xray_config(self, node: Node | None = None, *, tun_mode: bool = False) -> XrayRuntimeConfig:
        return build_runtime_xray_config_operation(self, node, tun_mode=tun_mode)

    def _transition_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return transition_signature_operation(self, node, settings, routing)

    def _xray_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return xray_layer_signature_operation(self, node, settings, routing)

    def _tun_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        return tun_layer_signature_operation(self, node, settings, routing)

    def _capture_active_session(
        self,
        node: Node | None,
        *,
        tun: bool,
        core: str,
        api_port: int,
        hybrid: bool = False,
        socks_port: int | None = None,
        http_port: int | None = None,
        xray_inbound_tags: tuple[str, ...] | None = None,
        sidecar_relay_port: int = 0,
        protect_ss_port: int = 0,
        protect_ss_password: str = "",
        ping_host: str = "",
        ping_port: int = 0,
    ) -> None:
        settings = self.state.settings
        routing = self.state.routing
        if socks_port is None:
            socks_port = int(DEFAULT_SOCKS_PORT)
        if http_port is None:
            http_port = int(DEFAULT_HTTP_PORT)
        if xray_inbound_tags is None:
            xray_inbound_tags = ()
        if not ping_host and node is not None:
            ping_host = node.server
        if ping_port <= 0 and node is not None:
            ping_port = int(node.port)
        proxy_bypass_lan = bool(routing.bypass_lan) if tun else self._system_proxy_bypass_lan(settings)
        self._active_session = build_active_session_snapshot(
            node_id=node.id if node else None,
            node_server=node.server if node else "",
            active_core=core,
            tun_mode=bool(tun),
            tun_engine=str(settings.tun_engine),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=proxy_bypass_lan,
            xray_path=str(settings.xray_path),
            singbox_path=str(settings.singbox_path),
            socks_port=int(socks_port),
            http_port=int(http_port),
            routing_signature=self._routing_signature(routing),
            transition_signature=self._transition_signature(node, settings, routing),
            xray_layer_signature=self._xray_layer_signature(node, settings, routing),
            tun_layer_signature=self._tun_layer_signature(node, settings, routing),
            hybrid=hybrid,
            api_port=int(api_port),
            xray_inbound_tags=tuple(xray_inbound_tags),
            sidecar_relay_port=int(sidecar_relay_port),
            protect_ss_port=int(protect_ss_port),
            protect_ss_password=str(protect_ss_password),
            ping_host=str(ping_host),
            ping_port=int(ping_port),
        )
        self._blocked_transition_signature = ""

    def _clear_active_session(self) -> None:
        self._active_session = None

    def _apply_proxy_runtime_change(self) -> bool:
        settings = self.state.settings
        bypass_lan = self._system_proxy_bypass_lan()
        if self._active_session is not None:
            socks_port = self._active_session.socks_port
            http_port = self._active_session.http_port
        else:
            socks_port, http_port = self.get_effective_proxy_ports()
        try:
            if settings.enable_system_proxy:
                self.proxy.enable(
                    http_port,
                    socks_port,
                    bypass_lan=bypass_lan,
                )
            else:
                self.proxy.disable(restore_previous=True)
        except Exception as exc:
            self._set_connection_status(
                "error",
                f"Не удалось применить системный прокси: {exc}",
                level="error",
            )
            return False

        node = self.selected_node
        if self.connected:
            self._capture_active_session(
                node,
                tun=False,
                core="xray",
                api_port=self._active_session.api_port if self._active_session else self._xray_api_port,
                socks_port=socks_port,
                http_port=http_port,
                xray_inbound_tags=self._active_session.xray_inbound_tags if self._active_session else (),
                ping_host=self._active_session.ping_host if self._active_session else "",
                ping_port=self._active_session.ping_port if self._active_session else 0,
            )
        return True

    def _needs_transition(self) -> bool:
        node = self.selected_node
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=self._active_session,
            can_apply_proxy_runtime_change=False,
            can_tun_hot_swap=False,
            can_proxy_hot_swap=False,
        )
        return needs_transition(context)

    def _can_apply_proxy_runtime_change(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        return can_apply_proxy_runtime_change_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            current_xray_layer_signature=self._xray_layer_signature(),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=self._system_proxy_bypass_lan(),
        )

    def _can_proxy_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        return can_proxy_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            socks_port=int(socks_port),
            http_port=int(http_port),
            current_xray_layer_signature=self._xray_layer_signature(),
        )

    def _can_tun_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        node = self.selected_node
        return can_tun_hot_swap_rule(
            session=session,
            settings_tun_mode=bool(settings.tun_mode),
            settings_tun_engine=str(settings.tun_engine),
            has_selected_node=node is not None,
            current_tun_layer_signature=self._tun_layer_signature(node, settings, self.state.routing),
        )

    def _compute_transition_action(self) -> str | None:
        node = self.selected_node
        session = self._active_session
        context = TransitionContext(
            desired_connected=self._desired_connected,
            locked=self.locked,
            has_selected_node=node is not None,
            can_connect_without_selected_node=self._can_connect_without_selected_node(),
            connected=self.connected,
            blocked_transition_signature=self._blocked_transition_signature,
            current_transition_signature=self._transition_signature(node),
            active_session=session,
            can_apply_proxy_runtime_change=self._can_apply_proxy_runtime_change(session) if session is not None else False,
            can_tun_hot_swap=self._can_tun_hot_swap(session) if session is not None else False,
            can_proxy_hot_swap=self._can_proxy_hot_swap(session) if session is not None else False,
        )
        return compute_transition_action(context)

    def _transition_status_text(self, action: str) -> str:
        return transition_status_text(action)

    def _request_transition(self, reason: str) -> None:
        self._blocked_transition_signature = ""
        self._transition_pending = True
        self._transition_reason = reason
        self._transition_generation += 1
        if self._transition_active or self._transition_scheduled:
            return
        self._transition_scheduled = True
        QTimer.singleShot(0, self._drain_transition_queue)

    def _drain_transition_queue(self) -> None:
        self._transition_scheduled = False
        if self._transition_active:
            return

        if not self._transition_pending and not self._needs_transition():
            self.transition_state_changed.emit(False, "")
            return

        action = self._compute_transition_action()
        if action is None:
            self._transition_pending = False
            self.transition_state_changed.emit(False, "")
            return

        self._transition_pending = False
        reason = self._transition_reason or action
        self._transition_active = True
        self.transition_state_changed.emit(True, self._transition_status_text(action))
        try:
            ok = self._run_transition_action(action, reason)
            if ok:
                self._blocked_transition_signature = ""
            else:
                self._blocked_transition_signature = self._transition_signature()
                self._desired_connected = self.connected
        finally:
            self._transition_active = False
            if self._transition_pending or self._needs_transition():
                self._transition_scheduled = True
                QTimer.singleShot(0, self._drain_transition_queue)
            else:
                self.transition_state_changed.emit(False, "")

    def _run_transition_action(self, action: str, reason: str) -> bool:
        if action == "disconnect":
            return self.disconnect_current()
        if action == "connect":
            return self.connect_selected()
        if action == "proxy_update":
            return self._apply_proxy_runtime_change()
        if action == "proxy_hot_swap":
            return self._restart_proxy_core(reason)
        if action == "tun_hot_swap":
            return self._hot_swap_node(reason)
        return self._reconnect(reason)

    # ── Country detection helpers ──

    def _detect_countries_sync(self) -> None:
        detect_countries_sync_operation(self)

    def _start_country_ip_resolution(self) -> None:
        start_country_ip_resolution_operation(self)

    def _on_countries_resolved(self, results: dict[str, str]) -> None:
        on_countries_resolved_operation(self, results)

    def shutdown(self) -> None:
        shutdown_operation(self)

    @staticmethod
    def _cleanup_tun_adapter() -> None:
        """Remove the wintun TUN adapter if it was left behind."""
        import subprocess as _sp
        try:
            result = run_text(
                ["netsh", "interface", "show", "interface"],
                timeout=5,
                creationflags=0x08000000,
            )
            if "ZapretKVN_TUN" in result_output_text(result):
                _sp.run(
                    ["netsh", "interface", "set", "interface", "ZapretKVN_TUN", "admin=disable"],
                    capture_output=True, timeout=5,
                    creationflags=0x08000000,
                )
        except Exception:
            pass

    @property
    def selected_node(self) -> Node | None:
        return self._get_node_by_id(self.state.selected_node_id)

    def _get_node_by_id(self, node_id: str | None) -> Node | None:
        return get_node_by_id_operation(self, node_id)

    def _prepare_node_for_runtime(self, node: Node | None) -> str | None:
        return prepare_node_for_runtime_operation(self, node)

    def export_node_outbound_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        return json.dumps(node.outbound, ensure_ascii=True, indent=2)

    def export_runtime_config_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        try:
            if self.is_singbox_editor_mode():
                plan = self._plan_runtime_singbox(node)
                return json.dumps(plan.singbox_config, ensure_ascii=True, indent=2)
            if self.uses_xray_raw_config():
                runtime = self._build_runtime_xray_config(node, tun_mode=self.is_xray_tun_mode())
                return json.dumps(runtime.config, ensure_ascii=True, indent=2)
            if not node:
                return None
            problem = self._prepare_node_for_runtime(node)
            if problem:
                return None
            cfg = build_xray_config(
                node,
                self.state.routing,
                self.state.settings,
                socks_port=DEFAULT_SOCKS_PORT,
                http_port=DEFAULT_HTTP_PORT,
            )
            return json.dumps(cfg, ensure_ascii=True, indent=2)
        except ValueError:
            return None

    def import_nodes_from_text(self, text: str) -> tuple[int, list[str]]:
        return import_nodes_from_text_operation(self, text)

    def remove_nodes(self, node_ids: set[str]) -> None:
        remove_nodes_operation(self, node_ids)

    def update_node(self, node_id: str, updates: dict) -> bool:
        return update_node_operation(self, node_id, updates)

    def bulk_update_nodes(self, node_ids: set[str], operations: dict) -> int:
        return bulk_update_nodes_operation(self, node_ids, operations)

    def get_all_groups(self) -> list[str]:
        return get_all_groups_operation(self)

    def get_all_tags(self) -> list[str]:
        return get_all_tags_operation(self)

    def _migrate_sort_order(self) -> None:
        if self.state.nodes and all(n.sort_order == 0 for n in self.state.nodes):
            for i, node in enumerate(self.state.nodes):
                node.sort_order = i + 1
            self.save()

    def reorder_nodes(self, node_id: str, direction: str) -> None:
        reorder_nodes_operation(self, node_id, direction)

    def set_selected_node(self, node_id: str) -> None:
        set_selected_node_operation(self, node_id)

    def _set_connection_status(self, phase: str, message: str, level: str | None = None) -> None:
        self.connection_status_changed.emit(phase, message)
        if level is not None:
            self.status.emit(level, message)

    def _compute_connected_state(self) -> bool:
        if self._active_core == "singbox":
            if self._active_session is not None and self._active_session.hybrid:
                return self.singbox.is_running and self.xray.is_running
            return self.singbox.is_running
        if self._active_core == "tun2socks":
            return self.tun2socks.is_running and self.xray.is_running
        return self.xray.is_running

    def _refresh_connected_state(self) -> tuple[bool, bool]:
        previous = self.connected
        self.connected = self._compute_connected_state()
        return previous, self.connected

    def _reset_auto_switch_state(self, *, reset_cooldown: bool = False, reset_cycle: bool = True) -> None:
        self._auto_switch_low_since = 0.0
        self._auto_switch_high_ticks = 0
        self._auto_switch_active_download = False
        if reset_cycle:
            self._auto_switch_cycle_attempts = 0
            self._auto_switch_exhausted = False
        if reset_cooldown:
            self._auto_switch_last_switch = 0.0

    def _cleanup_connection_runtime_state(
        self,
        *,
        end_traffic_session: bool,
        reset_auto_switch_cycle: bool,
        reset_auto_switch_cooldown: bool,
    ) -> None:
        cleanup_connection_runtime_state_operation(
            self,
            end_traffic_session=end_traffic_session,
            reset_auto_switch_cycle=reset_auto_switch_cycle,
            reset_auto_switch_cooldown=reset_auto_switch_cooldown,
        )

    def _stop_active_connection_processes(self, *, disable_proxy: bool) -> bool:
        return stop_active_connection_processes_operation(self, disable_proxy=disable_proxy)

    def _handle_unexpected_disconnect(self) -> None:
        handle_unexpected_disconnect_operation(self)

    def connect_selected(self, allow_during_reconnect: bool = False) -> bool:
        return connect_selected_operation(self, allow_during_reconnect=allow_during_reconnect)

    def disconnect_current(self, disable_proxy: bool = True, emit_status: bool = True) -> bool:
        return disconnect_current_operation(self, disable_proxy=disable_proxy, emit_status=emit_status)

    def _restart_proxy_core(self, reason: str) -> bool:
        return restart_xray_proxy_core(self, reason)

    def _restart_singbox_runtime(self, reason: str) -> bool:
        return restart_singbox_runtime_operation(self, reason)

    @property
    def traffic_history(self) -> TrafficHistoryStorage:
        return self._traffic_history

    def toggle_connection(self) -> None:
        current_target = self._desired_connected if (self._transition_active or self._transition_pending) else self.connected
        self._desired_connected = not current_target
        self._request_transition("toggle connection")

    def switch_next_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index + 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def switch_prev_node(self) -> None:
        if not self.state.nodes:
            return
        current_id = self.state.selected_node_id
        index = 0
        if current_id:
            for idx, node in enumerate(self.state.nodes):
                if node.id == current_id:
                    index = idx
                    break
        index = (index - 1) % len(self.state.nodes)
        self.set_selected_node(self.state.nodes[index].id)

    def update_routing(self, routing: RoutingSettings) -> None:
        if routing.mode not in ROUTING_MODES:
            routing.mode = "rule"
        self.state.routing = routing
        self.routing_changed.emit(self.state.routing)
        self.schedule_save()

        if self.connected or self._desired_connected:
            if not self.is_tun2socks_mode():
                return
            self._request_transition("routing changed")

    def update_settings(self, settings: AppSettings) -> None:
        old_settings = self.state.settings
        old_launch = old_settings.launch_on_startup
        old_launch_in_tray = old_settings.launch_in_tray
        old_tun = old_settings.tun_mode
        old_tun_engine = old_settings.tun_engine
        self.state.settings = settings
        self.settings_changed.emit(self.state.settings)
        self.schedule_save()

        if old_launch != settings.launch_on_startup or old_launch_in_tray != settings.launch_in_tray:
            try:
                set_startup_enabled(
                    APP_NAME,
                    settings.launch_on_startup,
                    build_startup_command(settings.launch_in_tray),
                )
            except Exception as exc:
                self.status.emit("error", f"Ошибка настройки автозапуска: {exc}")

        if self.connected or self._desired_connected:
            if old_tun != settings.tun_mode:
                self._desired_connected = True
                self._request_transition("TUN mode toggled")
                return
            if settings.tun_mode and old_tun_engine != settings.tun_engine:
                self._desired_connected = True
                self._request_transition("TUN engine changed")
                return
            self._request_transition("settings changed")

    def ping_nodes(self, node_ids: set[str] | None = None) -> None:
        ping_nodes_operation(self, node_ids)

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> bool:
        return speed_test_nodes_operation(self, node_ids)

    def cancel_speed_test(self) -> bool:
        return cancel_speed_test_operation(self)

    def get_fastest_alive_node(self) -> Node | None:
        return get_fastest_alive_node_operation(self)

    def test_connectivity(self, url: str | None = None) -> None:
        test_connectivity_operation(self, url)

    def run_xray_core_update(self, apply_update: bool, silent: bool = False) -> None:
        run_xray_core_update_operation(self, apply_update, silent=silent)

    def _start_metrics_worker(self) -> None:
        start_metrics_worker_operation(self)

    def _stop_metrics_worker(self) -> None:
        stop_metrics_worker_operation(self)

    def set_master_password(self, password: str) -> None:
        password_hash, salt = create_password_hash(password)
        self.state.security.enabled = True
        self.state.security.password_hash = password_hash
        self.state.security.salt = salt
        self.save()

    def disable_master_password(self) -> None:
        self.state.security.enabled = False
        self.state.security.password_hash = ""
        self.state.security.salt = ""
        self.locked = False
        self.lock_state_changed.emit(False)
        self.save()

    def unlock(self, password: str) -> bool:
        if not self.state.security.enabled:
            self.locked = False
            self.lock_state_changed.emit(False)
            return True

        ok = verify_password(password, self.state.security.password_hash, self.state.security.salt)
        if ok:
            self.locked = False
            self.lock_state_changed.emit(False)
        return ok

    def lock(self) -> None:
        if not self.state.security.enabled:
            return
        self.locked = True
        self.lock_state_changed.emit(True)
        self._desired_connected = False
        self.disconnect_current()

    def build_diagnostics(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = LOG_DIR / f"diagnostics_{stamp}.zip"
        return export_diagnostics(output, self.state, self.recent_logs)

    def auto_connect_if_needed(self) -> None:
        if not self.state.settings.auto_connect_last or self.locked:
            return
        if self.selected_node is None and not self._can_connect_without_selected_node():
            return
        if self.selected_node is not None or self._can_connect_without_selected_node():
            self._desired_connected = True
            self._request_transition("auto connect")

    def _log(self, line: str) -> None:
        """Send a log line to the UI and write it to the log file."""
        self.recent_logs.append(line)
        if len(self.recent_logs) > 5000:
            self.recent_logs = self.recent_logs[-5000:]
        self._logger.info(line)
        self.log_line.emit(line)

    def _on_xray_log(self, line: str) -> None:
        # In TUN mode, throttle noisy per-connection logs to prevent UI freeze
        if self.state.settings.tun_mode and "accepted" in line:
            self._tun_log_count = getattr(self, "_tun_log_count", 0) + 1
            # Only log to file, skip UI — emit summary every 100 lines
            self._logger.info(line)
            self.recent_logs.append(line)
            if len(self.recent_logs) > 5000:
                self.recent_logs = self.recent_logs[-5000:]
            if self._tun_log_count % 100 == 0:
                self.log_line.emit(f"[tun] {self._tun_log_count} connections routed...")
            return
        self._log(line)

    def _on_xray_error(self, message: str) -> None:
        self._log(f"[xray-error] {message}")
        self._set_connection_status("error", message, level="error")

    def _on_singbox_error(self, message: str) -> None:
        self._log(f"[singbox-error] {message}")
        self._set_connection_status("error", message, level="error")

    def _on_core_stopped(self, core: str, exit_code: int) -> None:
        self._log(f"[{core}] process stopped with code {exit_code}")

    def _on_core_state_changed(self, _running: bool) -> None:
        on_core_state_changed_operation(self, _running)

    def _on_ping_result(self, node_id: str, ping_ms: int | None) -> None:
        on_ping_result_operation(self, node_id, ping_ms)

    def _on_ping_progress(self, current: int, total: int) -> None:
        on_ping_progress_operation(self, current, total)

    def _on_ping_complete(self) -> None:
        on_ping_complete_operation(self)

    def _on_speed_result(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        on_speed_result_operation(self, node_id, speed_mbps, is_alive)

    def _on_speed_progress(self, current: int, total: int) -> None:
        on_speed_progress_operation(self, current, total)

    def _on_speed_node_progress(self, node_id: str, percent: int) -> None:
        on_speed_node_progress_operation(self, node_id, percent)

    def _on_speed_complete(self) -> None:
        on_speed_complete_operation(self)

    def _on_connectivity_result(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        on_connectivity_result_operation(self, ok, message, elapsed_ms)

    def _on_live_metrics(self, payload: dict[str, object]) -> None:
        on_live_metrics_operation(self, payload)

    # Require N consecutive high-speed readings to confirm "active download"
    _AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10  # ~10s of sustained traffic above threshold
    # Minimum speed to count as "traffic exists" (1 KB/s) vs idle (0)
    _AUTO_SWITCH_IDLE_BPS = 1024.0

    def _check_auto_switch(self, down_bps: float) -> None:
        check_auto_switch_operation(self, down_bps)

    def _get_next_node_for_auto_switch(self) -> Node | None:
        return get_next_node_for_auto_switch_operation(self)

    def _on_xray_update_worker_done(self, result: XrayCoreUpdateResult) -> None:
        on_xray_update_worker_done_operation(self, result)

    def _on_network_changed(self, old: str, new: str) -> None:
        self._log(f"[network] changed: {old} -> {new}")
        # TUN mode creates a virtual adapter which triggers network change —
        # reconnecting would kill the TUN and cause an infinite loop
        if self.state.settings.tun_mode:
            self._log("[network] ignoring change in TUN mode")
            return
        if self.connected and self.state.settings.reconnect_on_network_change:
            self._desired_connected = True
            self._request_transition("network changed")

    def _hot_swap_node(self, reason: str) -> bool:
        """Handle node switch while TUN is active."""
        node = self.selected_node
        session = self._active_session
        if session is None:
            self._auto_switch_transitioning = False
            return False

        self._xray_api_port = session.api_port
        self._protect_ss_port = session.protect_ss_port
        self._protect_ss_password = session.protect_ss_password

        if self._active_core == "singbox":
            try:
                return self._restart_singbox_runtime(reason)
            finally:
                self._auto_switch_transitioning = False

        # tun2socks mode: restart only xray while the TUN adapter stays up
        if self._active_core == "tun2socks":
            if node is None:
                self._auto_switch_transitioning = False
                return False
            try:
                return hot_swap_tun2socks(self, reason, node)
            finally:
                self._auto_switch_transitioning = False

        # sing-box raw mode keeps the user config as the source of truth and may
        # switch between native and hybrid planner outcomes, so reconnect.
        return self._reconnect(f"{reason} (sing-box config change)")

    def _reconnect(self, reason: str) -> bool:
        return reconnect_operation(self, reason)

    def export_backup(self, path: Path, passphrase: str = "") -> None:
        self.storage.export_backup(path, passphrase)

    def import_backup(self, path: Path, passphrase: str = "") -> None:
        self.state = self.storage.import_backup(path, passphrase)
        self.save()
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.routing_changed.emit(self.state.routing)
        self.settings_changed.emit(self.state.settings)

    def _check_auto_lock(self) -> None:
        if not self.state.security.enabled:
            return
        if self.locked:
            return
        minutes = max(1, self.state.security.auto_lock_minutes)
        if get_idle_seconds() >= minutes * 60:
            self.lock()
