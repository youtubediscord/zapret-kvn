from __future__ import annotations

from copy import deepcopy
import hashlib
import logging
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .country_flags import CountryResolver, detect_country
from .config_builder import build_xray_config
from .singbox_runtime_planner import (
    SingboxDocumentState,
    SingboxRuntimePlan,
    classify_node_for_singbox,
    inspect_singbox_document_text,
    parse_singbox_document,
    plan_singbox_runtime,
)
from .connectivity_test import ConnectivityTestWorker
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
from .link_parser import parse_links_text, repair_node_outbound_from_link, validate_node_outbound
from .live_metrics_worker import LiveMetricsWorker
from .models import AppSettings, AppState, Node, RoutingSettings
from .network_monitor import NetworkMonitor
from .ping_worker import PingWorker
from .speed_test_worker import SpeedTestWorker
from .proxy_manager import ProxyManager
from .security import create_password_hash, get_idle_seconds, verify_password
from .tun2socks_manager import Tun2SocksManager
from .singbox_manager import SingBoxManager, get_singbox_version
from .storage import PassphraseRequired, StateStorage
from .startup import build_startup_command, set_startup_enabled
from .subprocess_utils import result_output_text, run_text
from .xray_core_updater import XrayCoreUpdateResult, XrayCoreUpdateWorker
from .traffic_history import TrafficHistoryStorage
from .xray_manager import XrayManager, get_xray_version
from .xray_tun_route_manager import XrayTunRouteManager, get_windows_default_route_context
from .zapret_manager import ZapretManager


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

@dataclass(slots=True)
class ActiveSessionSnapshot:
    node_id: str | None
    node_server: str
    active_core: str
    tun_mode: bool
    tun_engine: str
    proxy_enabled: bool
    proxy_bypass_lan: bool
    xray_path: str
    singbox_path: str
    socks_port: int
    http_port: int
    routing_signature: str
    transition_signature: str
    xray_layer_signature: str
    tun_layer_signature: str
    hybrid: bool
    api_port: int
    xray_inbound_tags: tuple[str, ...]
    sidecar_relay_port: int
    protect_ss_port: int
    protect_ss_password: str
    ping_host: str
    ping_port: int

@dataclass(slots=True)
class XrayRuntimeConfig:
    config: dict[str, Any]
    source_path: Path
    has_proxy_outbound: bool
    used_selected_node: bool
    socks_port: int
    http_port: int
    api_port: int
    tun_interface_name: str
    loop_prevention_interface: str
    loop_prevention_patched_outbounds: int
    inbound_tags: tuple[str, ...]
    ping_host: str
    ping_port: int


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
        self._singbox_document_state: SingboxDocumentState | None = None
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
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def _routing_signature(self, routing: RoutingSettings | None = None) -> str:
        routing = routing or self.state.routing
        return self._signature(routing.to_dict())

    def is_singbox_editor_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "singbox")

    def is_xray_tun_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "xray")

    def is_legacy_tun2socks_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return bool(settings.tun_mode and str(settings.tun_engine) == "tun2socks")

    def uses_xray_raw_config(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return not self.is_singbox_editor_mode(settings) and not self.is_legacy_tun2socks_mode(settings)

    def is_xray_editor_mode(self, settings: AppSettings | None = None) -> bool:
        settings = settings or self.state.settings
        return not bool(settings.tun_mode)

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
        # System proxy bypass is an app-level network behavior, not part of raw
        # core configs and not part of removed RoutingSettings.
        settings = settings or self.state.settings
        return bool(settings.system_proxy_bypass_lan)

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
        raw = str(value or "").strip().replace("\\", "/")
        if not raw:
            return SINGBOX_DEFAULT_CONFIG_NAME

        parts = [part for part in Path(raw).parts if part not in ("", ".", "..", "/")]
        relative = Path(*parts) if parts else Path(SINGBOX_DEFAULT_CONFIG_NAME)
        if not relative.suffix:
            relative = relative.with_suffix(".json")
        return relative.as_posix()

    def _normalize_singbox_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_singbox_config_relative_path(value)

    def _resolve_singbox_config_path(self, path: str | Path | None = None) -> Path:
        base_dir = self.get_singbox_config_dir().resolve()
        if path is None or not str(path).strip():
            relative = Path(self._normalize_singbox_config_relative_path(self.state.settings.singbox_config_file))
            resolved = (base_dir / relative).resolve()
        else:
            candidate = Path(path)
            if candidate.is_absolute():
                resolved = candidate.resolve()
            else:
                resolved = (base_dir / self._normalize_singbox_config_relative_path(candidate)).resolve()

        if not resolved.suffix:
            resolved = resolved.with_suffix(".json")

        try:
            resolved.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError("Файл sing-box должен находиться в data/configs/sing-box/") from exc

        return resolved

    def _resolve_singbox_template_path(self, path: str | Path | None = None) -> Path:
        base_dir = self.get_singbox_template_dir().resolve()
        if path is None or not str(path).strip():
            relative = Path(self._normalize_singbox_template_relative_path(self.state.settings.singbox_template_file))
            resolved = (base_dir / relative).resolve()
        else:
            candidate = Path(path)
            if candidate.is_absolute():
                resolved = candidate.resolve()
            else:
                resolved = (base_dir / self._normalize_singbox_template_relative_path(candidate)).resolve()

        if not resolved.suffix:
            resolved = resolved.with_suffix(".json")

        try:
            resolved.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError("Файл sing-box template должен находиться в data/templates/sing-box/") from exc

        return resolved

    def _normalize_xray_config_relative_path(self, value: str | Path | None) -> str:
        raw = str(value or "").strip().replace("\\", "/")
        if not raw:
            return XRAY_DEFAULT_CONFIG_NAME

        parts = [part for part in Path(raw).parts if part not in ("", ".", "..", "/")]
        relative = Path(*parts) if parts else Path(XRAY_DEFAULT_CONFIG_NAME)
        if not relative.suffix:
            relative = relative.with_suffix(".json")
        return relative.as_posix()

    def _normalize_xray_template_relative_path(self, value: str | Path | None) -> str:
        return self._normalize_xray_config_relative_path(value)

    def _resolve_xray_config_path(self, path: str | Path | None = None) -> Path:
        base_dir = self.get_xray_config_dir().resolve()
        if path is None or not str(path).strip():
            relative = Path(self._normalize_xray_config_relative_path(self.state.settings.xray_config_file))
            resolved = (base_dir / relative).resolve()
        else:
            candidate = Path(path)
            if candidate.is_absolute():
                resolved = candidate.resolve()
            else:
                resolved = (base_dir / self._normalize_xray_config_relative_path(candidate)).resolve()

        if not resolved.suffix:
            resolved = resolved.with_suffix(".json")

        try:
            resolved.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError("Файл xray должен находиться в data/configs/xray/") from exc

        return resolved

    def _resolve_xray_template_path(self, path: str | Path | None = None) -> Path:
        base_dir = self.get_xray_template_dir().resolve()
        if path is None or not str(path).strip():
            relative = Path(self._normalize_xray_template_relative_path(self.state.settings.xray_template_file))
            resolved = (base_dir / relative).resolve()
        else:
            candidate = Path(path)
            if candidate.is_absolute():
                resolved = candidate.resolve()
            else:
                resolved = (base_dir / self._normalize_xray_template_relative_path(candidate)).resolve()

        if not resolved.suffix:
            resolved = resolved.with_suffix(".json")

        try:
            resolved.relative_to(base_dir)
        except ValueError as exc:
            raise ValueError("Файл xray template должен находиться в data/templates/xray/") from exc

        return resolved

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
        payload = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "xftun",
                    "address": ["172.19.0.1/30"],
                    "auto_route": True,
                    "strict_route": False,
                    "stack": "mixed",
                }
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "proxy",
                },
                {
                    "type": "direct",
                    "tag": "direct",
                },
                {
                    "type": "block",
                    "tag": "block",
                },
            ],
            "route": {
                "auto_detect_interface": True,
                "final": "direct",
            },
        }
        return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"

    @staticmethod
    def _default_xray_config_text() -> str:
        payload = {
            "log": {
                "loglevel": "warning",
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "listen": PROXY_HOST,
                    "port": DEFAULT_SOCKS_PORT,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True,
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True,
                    },
                },
                {
                    "tag": "http-in",
                    "listen": PROXY_HOST,
                    "port": DEFAULT_HTTP_PORT,
                    "protocol": "http",
                    "settings": {},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"],
                        "routeOnly": True,
                    },
                },
                {
                    "tag": "api",
                    "listen": PROXY_HOST,
                    "port": DEFAULT_XRAY_STATS_API_PORT,
                    "protocol": "dokodemo-door",
                    "settings": {
                        "address": PROXY_HOST,
                    },
                },
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "freedom",
                    "settings": {},
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {},
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {},
                },
                {
                    "tag": "api",
                    "protocol": "freedom",
                    "settings": {},
                },
            ],
            "policy": {
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True,
                }
            },
            "stats": {},
            "api": {
                "tag": "api",
                "services": ["StatsService"],
            },
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api",
                    },
                    {
                        "type": "field",
                        "network": "tcp,udp",
                        "outboundTag": "direct",
                    },
                ],
            },
        }
        return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"

    def get_active_singbox_config_path(self) -> Path:
        return self._resolve_singbox_config_path()

    def get_active_singbox_config_name(self) -> str:
        return self.get_active_singbox_config_path().name

    def get_active_singbox_template_path(self) -> Path | None:
        relative = self._normalize_singbox_template_relative_path(
            self.state.settings.singbox_template_file or self.state.settings.singbox_config_file
        )
        try:
            resolved = self._resolve_singbox_template_path(relative)
        except ValueError:
            return None
        return resolved if resolved.exists() else None

    def get_active_xray_config_path(self) -> Path:
        return self._resolve_xray_config_path()

    def get_active_xray_config_name(self) -> str:
        return self.get_active_xray_config_path().name

    def get_active_xray_template_path(self) -> Path | None:
        relative = self._normalize_xray_template_relative_path(
            self.state.settings.xray_template_file or self.state.settings.xray_config_file
        )
        try:
            resolved = self._resolve_xray_template_path(relative)
        except ValueError:
            return None
        return resolved if resolved.exists() else None

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
        state = inspect_singbox_document_text(path, text)
        self._singbox_document_state = state
        return state

    def _get_singbox_document_state(self) -> SingboxDocumentState:
        path = self._ensure_active_singbox_config()
        if self._singbox_document_state is not None and self._singbox_document_state.source_path == path:
            return self._singbox_document_state
        text = path.read_text(encoding="utf-8")
        return self._cache_singbox_document_state(path, text)

    def _default_singbox_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_singbox_config_dir().resolve()).as_posix()
        template = self._resolve_singbox_template_path(relative)
        return template if template.exists() else None

    def _default_xray_template_path_for_config(self, config_path: Path) -> Path | None:
        relative = config_path.relative_to(self.get_xray_config_dir().resolve()).as_posix()
        template = self._resolve_xray_template_path(relative)
        return template if template.exists() else None

    def _ensure_active_singbox_config(self, path: str | Path | None = None) -> Path:
        resolved = self._resolve_singbox_config_path(path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if not resolved.exists():
            template_path = self.get_active_singbox_template_path()
            if template_path is None and path is not None:
                template_path = self._default_singbox_template_path_for_config(resolved)
            if template_path is not None:
                resolved.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
                self._set_active_singbox_template_path(template_path, emit_signal=False)
            else:
                resolved.write_text(self._default_singbox_config_text(), encoding="utf-8")
        self._set_active_singbox_config_path(resolved)
        return resolved

    def _ensure_active_xray_config(self, path: str | Path | None = None) -> Path:
        resolved = self._resolve_xray_config_path(path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if not resolved.exists():
            template_path = self.get_active_xray_template_path()
            if template_path is None and path is not None:
                template_path = self._default_xray_template_path_for_config(resolved)
            if template_path is not None:
                resolved.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
                self._set_active_xray_template_path(template_path, emit_signal=False)
            else:
                resolved.write_text(self._default_xray_config_text(), encoding="utf-8")
        self._set_active_xray_config_path(resolved)
        return resolved

    def load_active_singbox_config_text(self) -> tuple[Path, str]:
        path = self._ensure_active_singbox_config()
        text = path.read_text(encoding="utf-8")
        self._cache_singbox_document_state(path, text)
        return path, text

    def load_active_xray_config_text(self) -> tuple[Path, str]:
        path = self._ensure_active_xray_config()
        return path, path.read_text(encoding="utf-8")

    def load_singbox_config_text(self, path: str | Path) -> tuple[Path, str]:
        resolved = self._resolve_singbox_config_path(path)
        if not resolved.exists():
            raise FileNotFoundError(f"Файл не найден: {resolved.name}")
        self._set_active_singbox_config_path(resolved)
        text = resolved.read_text(encoding="utf-8")
        self._cache_singbox_document_state(resolved, text)
        return resolved, text

    def load_xray_config_text(self, path: str | Path) -> tuple[Path, str]:
        resolved = self._resolve_xray_config_path(path)
        if not resolved.exists():
            raise FileNotFoundError(f"Файл не найден: {resolved.name}")
        self._set_active_xray_config_path(resolved)
        return resolved, resolved.read_text(encoding="utf-8")

    def import_singbox_template(self, path: str | Path) -> tuple[Path, str]:
        template_path = self._resolve_singbox_template_path(path)
        if not template_path.exists():
            raise FileNotFoundError(f"Файл не найден: {template_path.name}")
        relative = template_path.relative_to(self.get_singbox_template_dir().resolve()).as_posix()
        active_path = self._resolve_singbox_config_path(relative)
        active_path.parent.mkdir(parents=True, exist_ok=True)
        if not active_path.exists():
            active_path.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
        self._set_active_singbox_template_path(template_path)
        self._set_active_singbox_config_path(active_path)
        text = active_path.read_text(encoding="utf-8")
        self._cache_singbox_document_state(active_path, text)
        return active_path, text

    def import_xray_template(self, path: str | Path) -> tuple[Path, str]:
        template_path = self._resolve_xray_template_path(path)
        if not template_path.exists():
            raise FileNotFoundError(f"Файл не найден: {template_path.name}")
        relative = template_path.relative_to(self.get_xray_template_dir().resolve()).as_posix()
        active_path = self._resolve_xray_config_path(relative)
        active_path.parent.mkdir(parents=True, exist_ok=True)
        if not active_path.exists():
            active_path.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
        self._set_active_xray_template_path(template_path)
        self._set_active_xray_config_path(active_path)
        return active_path, active_path.read_text(encoding="utf-8")

    def reset_active_singbox_config_to_template(self) -> tuple[bool, Path | None, str]:
        template_path = self.get_active_singbox_template_path()
        if template_path is None:
            return False, None, "Для текущего sing-box конфига не привязан template."
        active_path = self._ensure_active_singbox_config()
        text = template_path.read_text(encoding="utf-8")
        active_path.write_text(text, encoding="utf-8")
        self._cache_singbox_document_state(active_path, text)
        return True, active_path, f"Активная копия сброшена к шаблону: {template_path.name}"

    def reset_active_xray_config_to_template(self) -> tuple[bool, Path | None, str]:
        template_path = self.get_active_xray_template_path()
        if template_path is None:
            return False, None, "Для текущего xray конфига не привязан template."
        active_path = self._ensure_active_xray_config()
        text = template_path.read_text(encoding="utf-8")
        active_path.write_text(text, encoding="utf-8")
        return True, active_path, f"Активная копия сброшена к шаблону: {template_path.name}"

    def save_singbox_config_text(self, text: str, path: str | Path | None = None) -> Path:
        resolved = self._ensure_active_singbox_config(path)
        resolved.write_text(text, encoding="utf-8")
        self._set_active_singbox_config_path(resolved)
        self._cache_singbox_document_state(resolved, text)
        return resolved

    def save_xray_config_text(self, text: str, path: str | Path | None = None) -> Path:
        resolved = self._ensure_active_xray_config(path)
        resolved.write_text(text, encoding="utf-8")
        self._set_active_xray_config_path(resolved)
        return resolved

    @staticmethod
    def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
        lines = text.splitlines()
        line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
        caret = ""
        if line:
            caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
        return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()

    def validate_json_text(self, text: str) -> tuple[bool, str]:
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            return False, self._format_json_error_message(text, exc)
        return True, "JSON корректен."

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
        ok, message = self.validate_json_text(text)
        if not ok:
            return False, None, message

        path = self.save_singbox_config_text(text)
        if self._active_core == "singbox" or (self.is_singbox_editor_mode() and (self.connected or self._desired_connected)):
            self._desired_connected = True
            self._request_transition("sing-box config applied")
            return True, path, "Конфиг сохранён. Применяю изменения sing-box..."

        return True, path, "Конфиг сохранён. Он будет использован при следующем запуске sing-box."

    def apply_xray_config_text(self, text: str) -> tuple[bool, Path | None, str]:
        ok, message = self.validate_json_text(text)
        if not ok:
            return False, None, message

        path = self.save_xray_config_text(text)
        if self._active_core == "xray" and (self.connected or self._desired_connected) and self.uses_xray_raw_config():
            self._desired_connected = True
            self._request_transition("xray config applied")
            return True, path, "Конфиг сохранён. Применяю изменения xray..."

        return True, path, "Конфиг сохранён. Он будет использован при следующем запуске xray."

    @staticmethod
    def _config_has_proxy_outbound(payload: Any) -> bool:
        if not isinstance(payload, dict):
            return False
        outbounds = payload.get("outbounds")
        if not isinstance(outbounds, list):
            return False
        return any(isinstance(outbound, dict) and outbound.get("tag") == "proxy" for outbound in outbounds)

    @staticmethod
    def _is_local_runtime_host(value: str) -> bool:
        host = str(value or "").strip().lower()
        return host in {"", "127.0.0.1", "::1", "localhost"}

    @staticmethod
    def _infer_singbox_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        host = str(outbound.get("server") or "").strip()
        try:
            port = int(outbound.get("server_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or port <= 0 or AppController._is_local_runtime_host(host):
            return "", 0
        return host, port

    @staticmethod
    def _infer_xray_outbound_endpoint(outbound: dict[str, Any]) -> tuple[str, int]:
        protocol = str(outbound.get("protocol") or "").strip().lower()
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            return "", 0

        host = ""
        port = 0
        if protocol in {"vless", "vmess"}:
            vnext = settings.get("vnext")
            if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
                host = str(vnext[0].get("address") or "").strip()
                try:
                    port = int(vnext[0].get("port") or 0)
                except (TypeError, ValueError):
                    port = 0
        elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
            servers = settings.get("servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                host = str(servers[0].get("address") or "").strip()
                try:
                    port = int(servers[0].get("port") or 0)
                except (TypeError, ValueError):
                    port = 0

        if not host or port <= 0 or AppController._is_local_runtime_host(host):
            return "", 0
        return host, port

    @staticmethod
    def _infer_singbox_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        if node is not None and node.server and node.port > 0:
            return node.server, node.port
        for outbound in payload.get("outbounds") or []:
            if not isinstance(outbound, dict):
                continue
            host, port = AppController._infer_singbox_outbound_endpoint(outbound)
            if host and port > 0:
                return host, port
        return "", 0

    @staticmethod
    def _infer_xray_ping_target(payload: dict[str, Any], node: Node | None) -> tuple[str, int]:
        if node is not None and node.server and node.port > 0:
            return node.server, node.port
        for outbound in payload.get("outbounds") or []:
            if not isinstance(outbound, dict):
                continue
            host, port = AppController._infer_xray_outbound_endpoint(outbound)
            if host and port > 0:
                return host, port
        return "", 0

    @staticmethod
    def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
        value = parent.get(key)
        if isinstance(value, dict):
            return value
        created: dict[str, Any] = {}
        parent[key] = created
        return created

    @staticmethod
    def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
        value = parent.get(key)
        if isinstance(value, list):
            return value
        created: list[Any] = []
        parent[key] = created
        return created

    @staticmethod
    def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
        for index, item in enumerate(items):
            if isinstance(item, dict) and str(item.get("tag") or "") == tag:
                items[index] = payload
                return
        items.append(payload)

    @staticmethod
    def _collect_xray_inbound_ports(payload: Any) -> set[int]:
        ports: set[int] = set()
        if not isinstance(payload, dict):
            return ports
        for inbound in payload.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            try:
                port = int(inbound.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if port > 0:
                ports.add(port)
        return ports

    def _ensure_xray_metrics_contract(
        self,
        payload: dict[str, Any],
        *,
        allocate_port: bool,
    ) -> tuple[int, tuple[str, ...]]:
        stats = payload.get("stats")
        if not isinstance(stats, dict):
            payload["stats"] = {}

        policy = self._ensure_dict(payload, "policy")
        system_policy = self._ensure_dict(policy, "system")
        system_policy["statsInboundUplink"] = True
        system_policy["statsInboundDownlink"] = True
        system_policy["statsOutboundUplink"] = True
        system_policy["statsOutboundDownlink"] = True

        outbounds = self._ensure_list(payload, "outbounds")
        api = self._ensure_dict(payload, "api")
        existing_api_tag = str(api.get("tag") or "").strip()
        api_tag = _XRAY_METRICS_API_TAG
        if existing_api_tag:
            for outbound in outbounds:
                if not isinstance(outbound, dict):
                    continue
                if str(outbound.get("tag") or "").strip() != existing_api_tag:
                    continue
                protocol = str(outbound.get("protocol") or "").strip().lower()
                if protocol in {"freedom", "loopback"}:
                    api_tag = existing_api_tag
                break
        api["tag"] = api_tag
        services = api.get("services")
        normalized_services = [str(item) for item in services] if isinstance(services, list) else []
        if "StatsService" not in normalized_services:
            normalized_services.append("StatsService")
        api["services"] = normalized_services

        inbounds = self._ensure_list(payload, "inbounds")
        existing_ports = self._collect_xray_inbound_ports(payload)

        preferred_api_port = 0
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("tag") or "") != _XRAY_METRICS_API_INBOUND_TAG:
                continue
            try:
                preferred_api_port = int(inbound.get("port") or 0)
            except (TypeError, ValueError):
                preferred_api_port = 0
            if preferred_api_port > 0:
                existing_ports.discard(preferred_api_port)
            break

        if preferred_api_port > 0:
            api_port = preferred_api_port
        elif allocate_port:
            try:
                api_port = _find_free_api_port(excluded=existing_ports)
            except RuntimeError as exc:
                raise ValueError("Не удалось выделить локальный порт для Xray metrics API.") from exc
        else:
            api_port = 0

        metrics_inbound = {
            "tag": _XRAY_METRICS_API_INBOUND_TAG,
            "listen": PROXY_HOST,
            "port": api_port,
            "protocol": "dokodemo-door",
            "settings": {
                "address": PROXY_HOST,
            },
        }
        self._replace_or_append_tagged(inbounds, _XRAY_METRICS_API_INBOUND_TAG, metrics_inbound)

        has_api_outbound = any(
            isinstance(outbound, dict) and str(outbound.get("tag") or "") == api_tag
            for outbound in outbounds
        )
        if not has_api_outbound:
            outbounds.append(
                {
                    "tag": api_tag,
                    "protocol": "freedom",
                    "settings": {},
                }
            )

        user_inbound_tags: list[str] = []
        for index, inbound in enumerate(inbounds):
            if not isinstance(inbound, dict):
                continue
            tag = str(inbound.get("tag") or "").strip()
            if tag == _XRAY_METRICS_API_INBOUND_TAG:
                continue
            if not tag:
                tag = f"__app_user_inbound_{index}"
                inbound["tag"] = tag
            if tag not in user_inbound_tags:
                user_inbound_tags.append(tag)

        routing = self._ensure_dict(payload, "routing")
        rules = self._ensure_list(routing, "rules")
        metrics_rule = {
            "type": "field",
            "inboundTag": [_XRAY_METRICS_API_INBOUND_TAG],
            "outboundTag": api_tag,
        }
        replaced = False
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            inbound_tags = rule.get("inboundTag")
            if isinstance(inbound_tags, list) and _XRAY_METRICS_API_INBOUND_TAG in [str(item) for item in inbound_tags]:
                rules[index] = metrics_rule
                replaced = True
                break
        if not replaced:
            rules.insert(0, metrics_rule)

        return api_port, tuple(user_inbound_tags)

    def _ensure_xray_tun_contract(self, payload: dict[str, Any]) -> str:
        inbounds = self._ensure_list(payload, "inbounds")
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("protocol") or "").strip().lower() != "tun":
                continue
            settings = self._ensure_dict(inbound, "settings")
            return str(settings.get("name") or "").strip() or XRAY_TUN_DEFAULT_INTERFACE_NAME

        inbounds.append(
            {
                "tag": _XRAY_TUN_INBOUND_TAG,
                "protocol": "tun",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            }
        )
        return XRAY_TUN_DEFAULT_INTERFACE_NAME

    @staticmethod
    def _xray_outbound_is_loop_protected(outbound: dict[str, Any]) -> bool:
        send_through = str(outbound.get("sendThrough") or "").strip()
        if send_through and send_through not in {"0.0.0.0", "::"}:
            return True
        stream_settings = outbound.get("streamSettings")
        if not isinstance(stream_settings, dict):
            return False
        sockopt = stream_settings.get("sockopt")
        if not isinstance(sockopt, dict):
            return False
        return bool(str(sockopt.get("interface") or "").strip())

    def _apply_xray_tun_loop_prevention(self, payload: dict[str, Any], interface_alias: str) -> int:
        patched = 0
        outbounds = self._ensure_list(payload, "outbounds")
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            tag = str(outbound.get("tag") or "").strip()
            protocol = str(outbound.get("protocol") or "").strip().lower()
            if tag in {_XRAY_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
                continue
            if self._xray_outbound_is_loop_protected(outbound):
                continue
            stream_settings = self._ensure_dict(outbound, "streamSettings")
            sockopt = self._ensure_dict(stream_settings, "sockopt")
            sockopt["interface"] = interface_alias
            patched += 1
        return patched

    def _inspect_active_singbox_config(self) -> tuple[Path, str, bool]:
        state = self._get_singbox_document_state()
        return state.source_path, state.text_hash, state.has_proxy_outbound

    @staticmethod
    def _extract_xray_runtime_ports(payload: Any) -> tuple[int, int, int]:
        socks_port = 0
        http_port = 0
        api_port = 0
        mixed_port = 0
        if not isinstance(payload, dict):
            return socks_port, http_port, api_port
        for inbound in payload.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            protocol = str(inbound.get("protocol") or "").strip().lower()
            tag = str(inbound.get("tag") or "").strip().lower()
            port_raw = inbound.get("port")
            try:
                port = int(port_raw or 0)
            except (TypeError, ValueError):
                port = 0
            if port <= 0:
                continue
            if protocol == "socks" and socks_port <= 0:
                socks_port = port
            elif protocol == "http" and http_port <= 0:
                http_port = port
            elif protocol == "mixed" and mixed_port <= 0:
                mixed_port = port
            elif tag == "api" and api_port <= 0:
                api_port = port
            elif tag == _XRAY_METRICS_API_INBOUND_TAG and api_port <= 0:
                api_port = port
        if socks_port <= 0 and mixed_port > 0:
            socks_port = mixed_port
        if http_port <= 0 and mixed_port > 0:
            http_port = mixed_port
        return socks_port, http_port, api_port

    def _inspect_active_xray_config(self) -> tuple[Path, str, bool, int, int, int]:
        path, text = self.load_active_xray_config_text()
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        has_proxy_outbound = False
        socks_port = 0
        http_port = 0
        api_port = 0
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            self._ensure_xray_metrics_contract(payload, allocate_port=False)
            has_proxy_outbound = self._config_has_proxy_outbound(payload)
            socks_port, http_port, api_port = self._extract_xray_runtime_ports(payload)
        return path, text_hash, has_proxy_outbound, socks_port, http_port, api_port

    def _plan_runtime_singbox(self, node: Node | None = None) -> SingboxRuntimePlan:
        source_path, text = self.load_active_singbox_config_text()
        document = parse_singbox_document(source_path, text)
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
        source_path, text = self.load_active_xray_config_text()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source_path.name}: {self._format_json_error_message(text, exc)}") from exc

        if not isinstance(payload, dict):
            raise ValueError("Корень xray config должен быть JSON-объектом.")

        tun_interface_name = ""
        if tun_mode:
            tun_interface_name = self._ensure_xray_tun_contract(payload)

        api_port, inbound_tags = self._ensure_xray_metrics_contract(payload, allocate_port=True)

        outbounds = payload.get("outbounds")
        has_proxy_outbound = False
        used_selected_node = False
        if isinstance(outbounds, list):
            for index, outbound in enumerate(outbounds):
                if not isinstance(outbound, dict) or outbound.get("tag") != "proxy":
                    continue
                has_proxy_outbound = True
                if node is None:
                    raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска xray.")
                problem = self._prepare_node_for_runtime(node)
                if problem:
                    raise ValueError(problem)
                proxy_outbound = deepcopy(node.outbound)
                proxy_outbound["tag"] = "proxy"
                outbounds[index] = proxy_outbound
                used_selected_node = True
                break

        loop_prevention_interface = ""
        loop_prevention_patched_outbounds = 0
        if tun_mode:
            needs_loop_patch = False
            if isinstance(outbounds, list):
                for outbound in outbounds:
                    if not isinstance(outbound, dict):
                        continue
                    tag = str(outbound.get("tag") or "").strip()
                    protocol = str(outbound.get("protocol") or "").strip().lower()
                    if tag in {_XRAY_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
                        continue
                    if not self._xray_outbound_is_loop_protected(outbound):
                        needs_loop_patch = True
                        break
            if needs_loop_patch:
                context = get_windows_default_route_context()
                if context is None:
                    raise ValueError(
                        "Не удалось определить активный сетевой интерфейс для xray TUN loop prevention. "
                        "Либо укажите streamSettings.sockopt.interface/sendThrough в raw xray config, "
                        "либо используйте sing-box TUN."
                    )
                loop_prevention_interface = context.interface_alias
                loop_prevention_patched_outbounds = self._apply_xray_tun_loop_prevention(
                    payload, loop_prevention_interface
                )

        socks_port, http_port, _ = self._extract_xray_runtime_ports(payload)
        ping_host, ping_port = self._infer_xray_ping_target(payload, node if used_selected_node else None)
        return XrayRuntimeConfig(
            config=payload,
            source_path=source_path,
            has_proxy_outbound=has_proxy_outbound,
            used_selected_node=used_selected_node,
            socks_port=socks_port,
            http_port=http_port,
            api_port=api_port,
            tun_interface_name=tun_interface_name,
            loop_prevention_interface=loop_prevention_interface,
            loop_prevention_patched_outbounds=loop_prevention_patched_outbounds,
            inbound_tags=inbound_tags,
            ping_host=ping_host,
            ping_port=ping_port,
        )

    def _transition_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        settings = settings or self.state.settings
        routing = routing or self.state.routing
        node = node or self.selected_node
        if self.is_singbox_editor_mode(settings):
            source_path, config_hash, has_proxy_outbound = self._inspect_active_singbox_config()
            planner_outcome = "native_singbox"
            if has_proxy_outbound and node is not None:
                planner_outcome = classify_node_for_singbox(node)
            signature_payload = {
                "mode": "singbox-editor",
                "singbox_path": str(settings.singbox_path),
                "config_file": str(source_path.name),
                "config_hash": config_hash,
                "has_proxy_outbound": has_proxy_outbound,
                "planner_outcome": planner_outcome,
                "node_id": node.id if has_proxy_outbound and node else None,
                "node_outbound": node.outbound if has_proxy_outbound and node else None,
            }
            if planner_outcome == "hybrid_xray_sidecar":
                signature_payload["xray_path"] = str(settings.xray_path)
            return self._signature(signature_payload)
        if self.uses_xray_raw_config(settings):
            source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = self._inspect_active_xray_config()
            signature_payload = {
                "mode": "xray-tun" if self.is_xray_tun_mode(settings) else "xray-direct",
                "xray_path": str(settings.xray_path),
                "config_file": str(source_path.name),
                "config_hash": config_hash,
                "has_proxy_outbound": has_proxy_outbound,
                "node_id": node.id if has_proxy_outbound and node else None,
                "node_outbound": node.outbound if has_proxy_outbound and node else None,
                "api_port": int(api_port),
            }
            if self.is_xray_tun_mode(settings):
                signature_payload.update(
                    {
                        "tun_mode": True,
                        "tun_engine": "xray",
                    }
                )
            else:
                signature_payload.update(
                    {
                        "proxy_enabled": bool(settings.enable_system_proxy),
                        "proxy_bypass_lan": self._system_proxy_bypass_lan(settings),
                        "socks_port": int(socks_port),
                        "http_port": int(http_port),
                    }
                )
            return self._signature(signature_payload)
        return self._signature(
            {
                "node_id": node.id if node else None,
                "tun_mode": bool(settings.tun_mode),
                "tun_engine": str(settings.tun_engine),
                "proxy_enabled": bool(settings.enable_system_proxy),
                "proxy_bypass_lan": bool(routing.bypass_lan),
                "socks_port": int(DEFAULT_SOCKS_PORT),
                "http_port": int(DEFAULT_HTTP_PORT),
                "xray_path": str(settings.xray_path),
                "singbox_path": str(settings.singbox_path),
                "routing": routing.to_dict(),
            }
        )

    def _xray_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        settings = settings or self.state.settings
        routing = routing or self.state.routing
        node = node or self.selected_node
        if self.uses_xray_raw_config(settings):
            source_path, config_hash, has_proxy_outbound, socks_port, http_port, api_port = self._inspect_active_xray_config()
            signature_payload = {
                "mode": "xray-tun" if self.is_xray_tun_mode(settings) else "xray-direct",
                "xray_path": str(settings.xray_path),
                "config_file": str(source_path.name),
                "config_hash": config_hash,
                "has_proxy_outbound": has_proxy_outbound,
                "node_id": node.id if has_proxy_outbound and node else None,
                "node_outbound": node.outbound if has_proxy_outbound and node else None,
                "socks_port": int(socks_port),
                "http_port": int(http_port),
                "api_port": int(api_port),
            }
            if self.is_xray_tun_mode(settings):
                signature_payload.update({"tun_mode": True, "tun_engine": "xray"})
            return self._signature(signature_payload)
        return self._signature(
            {
                "node_id": node.id if node else None,
                "tun_mode": bool(settings.tun_mode),
                "tun_engine": str(settings.tun_engine),
                "socks_port": int(DEFAULT_SOCKS_PORT),
                "http_port": int(DEFAULT_HTTP_PORT),
                "xray_path": str(settings.xray_path),
                "routing": routing.to_dict(),
            }
        )

    def _tun_layer_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        settings = settings or self.state.settings
        routing = routing or self.state.routing
        node = node or self.selected_node
        if not settings.tun_mode:
            return ""
        if self.is_singbox_editor_mode(settings):
            return self._transition_signature(node, settings, routing)
        if self.is_legacy_tun2socks_mode(settings):
            return self._signature(
                {
                    "mode": "tun2socks",
                    "server": node.server if node else "",
                    "socks_port": int(DEFAULT_SOCKS_PORT),
                }
            )
        if self.is_xray_tun_mode(settings):
            return self._signature(
                {
                    "mode": "xray-native-tun",
                    "xray_layer_signature": self._xray_layer_signature(node, settings, routing),
                }
            )
        return self._signature(
            {
                "mode": "singbox-native",
                "node_id": node.id if node else None,
                "node_outbound": (node.outbound if node else {}),
                "routing": routing.to_dict(),
                "xray_path": str(settings.xray_path),
                "singbox_path": str(settings.singbox_path),
            }
        )

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
        self._active_session = ActiveSessionSnapshot(
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
        if self._desired_connected:
            node = self.selected_node
            if self.locked:
                return False
            if node is None and not self._can_connect_without_selected_node():
                return False
            signature = self._transition_signature(node)
            if signature == self._blocked_transition_signature:
                return False
            if not self.connected or self._active_session is None:
                return True
            return self._active_session.transition_signature != signature
        return self.connected

    def _can_apply_proxy_runtime_change(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        if session.active_core != "xray" or session.tun_mode or settings.tun_mode:
            return False
        if session.xray_layer_signature != self._xray_layer_signature():
            return False
        return (
            session.proxy_enabled != bool(settings.enable_system_proxy)
            or session.proxy_bypass_lan != self._system_proxy_bypass_lan()
        )

    def _can_proxy_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        if session.active_core != "xray" or session.tun_mode or settings.tun_mode:
            return False
        _, _, _, socks_port, http_port, _ = self._inspect_active_xray_config()
        if session.socks_port != int(socks_port) or session.http_port != int(http_port):
            return False
        return session.xray_layer_signature != self._xray_layer_signature()

    def _can_tun_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        node = self.selected_node
        if not settings.tun_mode or not session.tun_mode:
            return False
        if session.tun_engine != str(settings.tun_engine):
            return False
        if session.active_core == "tun2socks":
            if node is None:
                return False
            if settings.tun_engine != "tun2socks":
                return False
            return session.tun_layer_signature == self._tun_layer_signature(node, settings, self.state.routing)

        return False

    def _compute_transition_action(self) -> str | None:
        if not self._desired_connected:
            return "disconnect" if self.connected else None

        node = self.selected_node
        if self.locked:
            return None
        if node is None and not self._can_connect_without_selected_node():
            return None
        if not self.connected or self._active_session is None:
            return "connect"

        session = self._active_session
        if session.transition_signature == self._transition_signature(node):
            return None
        if self._can_apply_proxy_runtime_change(session):
            return "proxy_update"
        if self._can_tun_hot_swap(session):
            return "tun_hot_swap"
        if self._can_proxy_hot_swap(session):
            return "proxy_hot_swap"
        return "reconnect"

    def _transition_status_text(self, action: str) -> str:
        mapping = {
            "connect": "Подключение...",
            "disconnect": "Отключение...",
            "proxy_update": "Применение системного прокси...",
            "proxy_hot_swap": "Переключение сервера...",
            "tun_hot_swap": "Переключение сервера...",
            "reconnect": "Переподключение...",
        }
        return mapping.get(action, "Применение изменений...")

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
        changed = False
        for node in self.state.nodes:
            if not node.country_code:
                code = detect_country(node.name, node.server)
                if code:
                    node.country_code = code
                    changed = True
        if changed:
            self.save()

    def _start_country_ip_resolution(self) -> None:
        needs = [(n.id, n.server) for n in self.state.nodes if not n.country_code]
        if not needs:
            return
        self._country_resolver = CountryResolver(needs, parent=self)
        self._country_resolver.resolved.connect(self._on_countries_resolved)
        self._country_resolver.start()

    def _on_countries_resolved(self, results: dict[str, str]) -> None:
        if not results:
            return
        for node in self.state.nodes:
            if node.id in results:
                node.country_code = results[node.id]
        self.save()
        self.nodes_changed.emit(self.state.nodes)

    def shutdown(self) -> None:
        if self._country_resolver and self._country_resolver.isRunning():
            self._country_resolver.quit()
            self._country_resolver.wait(2000)
        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.cancel()
            self._ping_worker.wait(500)
        if self._connectivity_worker and self._connectivity_worker.isRunning():
            self._connectivity_worker.wait(1000)
        self._stop_metrics_worker()
        if self._speed_worker and self._speed_worker.isRunning():
            self._speed_worker.cancel()
            self._speed_worker.wait(20000)
        if self._xray_update_worker and self._xray_update_worker.isRunning():
            self._xray_update_worker.wait(1000)

        self.disconnect_current()
        # Ensure all cores are stopped
        if self.tun2socks.is_running:
            self.tun2socks.stop()
        if self.singbox.is_running:
            self.singbox.stop()
        if self.xray.is_running:
            self.xray.stop()
        self._xray_tun_routes.cleanup()
        if self.zapret.running:
            self.zapret.stop()
        # Always disable system proxy on exit to prevent leaked proxy
        if self.proxy.is_enabled():
            self.proxy.disable(restore_previous=True)
        # Remove lingering TUN adapter
        self._cleanup_tun_adapter()
        self.network_monitor.stop()
        self._lock_timer.stop()
        self.save()

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
        if not node_id:
            return None
        for node in self.state.nodes:
            if node.id == node_id:
                return node
        return None

    def _prepare_node_for_runtime(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if repair_node_outbound_from_link(node):
            self.schedule_save()
        return validate_node_outbound(node)

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
        nodes, errors = parse_links_text(text)
        if not nodes:
            return 0, errors

        existing_links = {node.link for node in self.state.nodes}
        max_order = max((n.sort_order for n in self.state.nodes), default=0)
        first_new_id: str | None = None
        added = 0
        for node in nodes:
            problem = validate_node_outbound(node)
            if problem:
                errors.append(problem)
                continue
            if node.link in existing_links:
                continue
            if not node.country_code:
                node.country_code = detect_country(node.name, node.server)
            max_order += 1
            node.sort_order = max_order
            self.state.nodes.append(node)
            existing_links.add(node.link)
            if first_new_id is None:
                first_new_id = node.id
            added += 1

        if first_new_id:
            self.state.selected_node_id = first_new_id
        elif not self.state.selected_node_id and self.state.nodes:
            self.state.selected_node_id = self.state.nodes[0].id

        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()
        QTimer.singleShot(500, self._start_country_ip_resolution)

        if added:
            self._desired_connected = True
            self._request_transition("new node imported")

        return added, errors

    def remove_nodes(self, node_ids: set[str]) -> None:
        if not node_ids:
            return
        removed_selected = self.state.selected_node_id in node_ids
        should_reconcile = removed_selected and (self.connected or self._desired_connected)
        self.state.nodes = [node for node in self.state.nodes if node.id not in node_ids]
        if removed_selected:
            self.state.selected_node_id = self.state.nodes[0].id if self.state.nodes else None
            self._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
        self.nodes_changed.emit(self.state.nodes)
        self.selection_changed.emit(self.selected_node)
        self.save()
        if not should_reconcile:
            return
        if self.state.selected_node_id is None:
            if self._can_connect_without_selected_node():
                self._request_transition("active node removed")
                return
            self._desired_connected = False
            self._request_transition("active node removed")
            return
        self._desired_connected = True
        self._request_transition("active node removed")

    def update_node(self, node_id: str, updates: dict) -> bool:
        node = self._get_node_by_id(node_id)
        if not node:
            return False
        if "name" in updates:
            node.name = updates["name"]
        if "group" in updates:
            node.group = updates["group"]
        if "tags" in updates:
            node.tags = list(updates["tags"])
        self.nodes_changed.emit(self.state.nodes)
        self.save()
        return True

    def bulk_update_nodes(self, node_ids: set[str], operations: dict) -> int:
        group = operations.get("group", "")
        add_tags = operations.get("add_tags", [])
        remove_tags = set(operations.get("remove_tags", []))
        updated = 0
        for node in self.state.nodes:
            if node.id not in node_ids:
                continue
            if group:
                node.group = group
            if add_tags:
                existing = set(node.tags)
                for tag in add_tags:
                    if tag not in existing:
                        node.tags.append(tag)
            if remove_tags:
                node.tags = [t for t in node.tags if t not in remove_tags]
            updated += 1
        if updated:
            self.nodes_changed.emit(self.state.nodes)
            self.save()
        return updated

    def get_all_groups(self) -> list[str]:
        groups = {node.group for node in self.state.nodes if node.group}
        return sorted(groups)

    def get_all_tags(self) -> list[str]:
        tags: set[str] = set()
        for node in self.state.nodes:
            tags.update(node.tags)
        return sorted(tags)

    def _migrate_sort_order(self) -> None:
        if self.state.nodes and all(n.sort_order == 0 for n in self.state.nodes):
            for i, node in enumerate(self.state.nodes):
                node.sort_order = i + 1
            self.save()

    def reorder_nodes(self, node_id: str, direction: str) -> None:
        ordered = sorted(self.state.nodes, key=lambda n: n.sort_order)
        idx = next((i for i, n in enumerate(ordered) if n.id == node_id), None)
        if idx is None:
            return
        if direction == "up" and idx > 0:
            ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
        elif direction == "down" and idx < len(ordered) - 1:
            ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
        elif direction == "top" and idx > 0:
            node = ordered.pop(idx)
            ordered.insert(0, node)
        elif direction == "bottom" and idx < len(ordered) - 1:
            node = ordered.pop(idx)
            ordered.append(node)
        else:
            return
        for i, node in enumerate(ordered):
            node.sort_order = i + 1
        self.nodes_changed.emit(self.state.nodes)
        self.save()

    def set_selected_node(self, node_id: str) -> None:
        if self.state.selected_node_id == node_id:
            return
        self.state.selected_node_id = node_id
        self._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
        self.selection_changed.emit(self.selected_node)
        self.schedule_save()
        if self.connected or self._desired_connected:
            self._desired_connected = True
            self._request_transition("node switched")

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
        self._xray_tun_routes.cleanup()
        self._xray_api_port = 0
        self._protect_ss_port = 0
        self._protect_ss_password = ""
        self._traffic_save_counter = 0
        self._reset_auto_switch_state(
            reset_cooldown=reset_auto_switch_cooldown,
            reset_cycle=reset_auto_switch_cycle,
        )
        if end_traffic_session:
            self._traffic_history.end_session()
        from .process_traffic_collector import reset_connection_tracking
        from .win_proc_monitor import clear_pid_cache
        reset_connection_tracking()
        clear_pid_cache()

    def _stop_active_connection_processes(self, *, disable_proxy: bool) -> bool:
        stopped = True

        if self._active_core == "singbox":
            if self.singbox.is_running:
                stopped = self.singbox.stop() and stopped
            if self.xray.is_running:
                stopped = self.xray.stop() and stopped
            if self.tun2socks.is_running:
                stopped = self.tun2socks.stop() and stopped
        elif self._active_core == "tun2socks":
            if self.tun2socks.is_running:
                stopped = self.tun2socks.stop() and stopped
            if self.xray.is_running:
                stopped = self.xray.stop() and stopped
            if self.singbox.is_running:
                stopped = self.singbox.stop() and stopped
        else:
            if self.xray.is_running:
                stopped = self.xray.stop() and stopped
            if self.singbox.is_running:
                stopped = self.singbox.stop() and stopped
            if self.tun2socks.is_running:
                stopped = self.tun2socks.stop() and stopped

        if disable_proxy and self.state.settings.enable_system_proxy:
            self.proxy.disable(restore_previous=True)

        return stopped

    def _handle_unexpected_disconnect(self) -> None:
        if self._cleaning_connection_state:
            return
        self._cleaning_connection_state = True
        try:
            self._cleanup_connection_runtime_state(
                end_traffic_session=True,
                reset_auto_switch_cycle=not self._auto_switch_transitioning,
                reset_auto_switch_cooldown=True,
            )
            self._stop_active_connection_processes(disable_proxy=not self._reconnecting)
            self._active_core = "xray"
            self._clear_active_session()
            if not self._reconnecting:
                self._desired_connected = False
        finally:
            self._auto_switch_transitioning = False
            self._cleaning_connection_state = False

    def connect_selected(self, allow_during_reconnect: bool = False) -> bool:
        if self._connecting:
            return False
        self._connecting = True
        try:
            if self._reconnecting and not allow_during_reconnect:
                self._set_connection_status("starting", "Переподключение...", level="info")
                return False

            if self.locked:
                self._set_connection_status(
                    "error",
                    "Приложение заблокировано. Разблокируйте для подключения.",
                    level="warning",
                )
                return False

            node = self.selected_node
            singbox_editor_mode = self.is_singbox_editor_mode()
            xray_raw_mode = self.uses_xray_raw_config()
            legacy_tun2socks_mode = self.is_legacy_tun2socks_mode()
            if node is None and not self._can_connect_without_selected_node():
                message = "Сначала выберите сервер."
                if singbox_editor_mode or xray_raw_mode:
                    message = "В конфиге есть outbound tag `proxy`. Сначала выберите сервер."
                self._set_connection_status("error", message, level="warning")
                return False

            self._reset_auto_switch_state(
                reset_cooldown=not self._auto_switch_transitioning,
                reset_cycle=not self._auto_switch_transitioning,
            )

            prev_active_core = self._active_core
            tun = self.state.settings.tun_mode
            self._xray_api_port = 0
            if legacy_tun2socks_mode:
                try:
                    self._xray_api_port = _find_free_api_port(
                        excluded={DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT},
                    )
                except RuntimeError:
                    self._set_connection_status("error", "Не удалось найти свободный порт для API Xray", level="error")
                    return False

            singbox_plan: SingboxRuntimePlan | None = None
            runtime_xray: XrayRuntimeConfig | None = None
            if singbox_editor_mode:
                session_label = node.name if node else self.get_active_singbox_config_name()
            elif xray_raw_mode:
                session_label = node.name if node else self.get_active_xray_config_name()
            else:
                session_label = node.name if node else "unknown"

            if node is not None and not singbox_editor_mode and not xray_raw_mode:
                problem = self._prepare_node_for_runtime(node)
                if problem:
                    self._set_connection_status("error", problem, level="error")
                    return False

            if tun:
                self._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
                self._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")

                if not _is_admin():
                    self._log("[tun] NOT admin — aborting")
                    self._set_connection_status(
                        "error",
                        "Режим TUN требует прав Администратора. Запустите приложение от имени Администратора.",
                        level="error",
                    )
                    return False

                # TUN doesn't use system proxy — disable if it was left on
                if self.proxy.is_enabled():
                    self.proxy.disable(restore_previous=True)

                self._tun_log_count = 0
                engine = self.state.settings.tun_engine

                if engine == "singbox":
                    self._active_core = "singbox"
                    try:
                        singbox_plan = self._plan_runtime_singbox(node)
                    except ValueError as exc:
                        self._active_core = prev_active_core
                        self._set_connection_status("error", str(exc), level="error")
                        return False

                    session_label = singbox_plan.source_path.name
                    if singbox_plan.used_selected_node and node is not None:
                        session_label = f"{singbox_plan.source_path.name} / {node.name}"
                    start_message = (
                        f"Запуск VPN: {session_label} (sing-box + xray sidecar)..."
                        if singbox_plan.is_hybrid
                        else f"Запуск VPN: {session_label}..."
                    )
                    self._set_connection_status("starting", start_message, level="info")
                    self._log(
                        f"[tun] sing-box planner outcome: {singbox_plan.outcome} "
                        f"from {singbox_plan.source_path}"
                    )
                    if singbox_plan.used_selected_node and node is not None:
                        if singbox_plan.is_hybrid:
                            self._log(
                                f"[tun] outbound tag 'proxy' replaced with local xray relay for unsupported node: {node.name}"
                            )
                        else:
                            self._log(f"[tun] outbound tag 'proxy' replaced from selected node: {node.name}")

                    if not self._start_singbox_runtime_plan(singbox_plan):
                        self._set_connection_status(
                            "error",
                            (
                                "Не удалось запустить sing-box hybrid runtime. Проверьте путь к Xray и наличие wintun.dll в core/."
                                if singbox_plan.is_hybrid
                                else "Не удалось создать TUN адаптер. Проверьте наличие wintun.dll в core/."
                            ),
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                elif engine == "xray":
                    self._active_core = "xray"
                    try:
                        runtime_xray = self._build_runtime_xray_config(node, tun_mode=True)
                    except ValueError as exc:
                        self._active_core = prev_active_core
                        self._set_connection_status("error", str(exc), level="error")
                        return False

                    session_label = runtime_xray.source_path.name
                    if runtime_xray.used_selected_node and node is not None:
                        session_label = f"{runtime_xray.source_path.name} / {node.name}"
                    self._set_connection_status("starting", f"Запуск VPN: {session_label}...", level="info")
                    self._log(f"[tun] starting xray TUN from {runtime_xray.source_path}")
                    if runtime_xray.used_selected_node and node is not None:
                        self._log(f"[tun] outbound tag 'proxy' replaced from selected node: {node.name}")
                    if runtime_xray.loop_prevention_patched_outbounds > 0:
                        self._log(
                            "[tun] xray loop prevention bound "
                            f"{runtime_xray.loop_prevention_patched_outbounds} outbound(s) to interface "
                            f"{runtime_xray.loop_prevention_interface}"
                        )

                    self._xray_api_port = runtime_xray.api_port
                    xray_ok = self.xray.start(self.state.settings.xray_path, runtime_xray.config)
                    if not xray_ok:
                        self._active_core = prev_active_core
                        return False
                    route_ok = self._xray_tun_routes.setup(runtime_xray.tun_interface_name)
                    if not route_ok:
                        self.xray.stop()
                        self._set_connection_status(
                            "error",
                            "Не удалось применить системный маршрут для Xray TUN. "
                            "Проверьте права Администратора и версию Xray-core с native TUN support.",
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                elif engine == "tun2socks":
                    # --- legacy tun2socks TUN path ---
                    self._active_core = "tun2socks"
                    config = build_xray_config(
                        node,
                        self.state.routing,
                        self.state.settings,
                        api_port=self._xray_api_port,
                        socks_port=DEFAULT_SOCKS_PORT,
                        http_port=DEFAULT_HTTP_PORT,
                    )
                    config["log"] = {"loglevel": "error"}
                    xray_ok = self.xray.start(self.state.settings.xray_path, config)
                    if not xray_ok:
                        self._log("[tun] xray start failed")
                        self._active_core = prev_active_core
                        return False
                    self._set_connection_status("starting", "Xray запущен. Создание TUN адаптера...", level="info")

                    socks_port = DEFAULT_SOCKS_PORT
                    self._log(f"[tun] starting tun2socks -> SOCKS 127.0.0.1:{socks_port}")
                    tun_ok = self.tun2socks.start(socks_port, server_ip=node.server)
                    self._log(f"[tun] tun2socks start result: {tun_ok}")
                    if not tun_ok:
                        self.xray.stop()
                        self._set_connection_status(
                            "error",
                            "Не удалось создать TUN адаптер. Проверьте наличие tun2socks и wintun.dll в core/.",
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                else:
                    self._active_core = prev_active_core
                    self._set_connection_status("error", f"Неизвестный TUN engine: {engine}", level="error")
                    return False
            else:
                self._active_core = "xray"
                self._set_connection_status("starting", f"Запуск прокси: {session_label}...", level="info")
                try:
                    runtime_xray = self._build_runtime_xray_config(node, tun_mode=False)
                except ValueError as exc:
                    self._active_core = prev_active_core
                    self._set_connection_status("error", str(exc), level="error")
                    return False

                session_label = runtime_xray.source_path.name
                if runtime_xray.used_selected_node and node is not None:
                    session_label = f"{runtime_xray.source_path.name} / {node.name}"
                self._set_connection_status("starting", f"Запуск прокси: {session_label}...", level="info")
                if runtime_xray.used_selected_node and node is not None:
                    self._log(f"[xray] outbound tag 'proxy' replaced from selected node: {node.name}")

                self._xray_api_port = runtime_xray.api_port
                ok = self.xray.start(self.state.settings.xray_path, runtime_xray.config)
                if not ok:
                    self._active_core = prev_active_core
                    return False

                if self.state.settings.enable_system_proxy:
                    if runtime_xray.http_port <= 0 or runtime_xray.socks_port <= 0:
                        self.xray.stop()
                        self._set_connection_status(
                            "error",
                            "В raw xray config нет HTTP/SOCKS inbound портов для включения системного прокси.",
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                    try:
                        self.proxy.enable(
                            runtime_xray.http_port,
                            runtime_xray.socks_port,
                            bypass_lan=self._system_proxy_bypass_lan(),
                        )
                    except Exception as exc:
                        self.xray.stop()
                        self._set_connection_status(
                            "error",
                            f"Не удалось включить системный прокси: {exc}",
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                else:
                    self.proxy.disable(restore_previous=True)

            session_node = node
            if singbox_editor_mode and singbox_plan is not None and not singbox_plan.used_selected_node:
                session_node = None
            if xray_raw_mode and runtime_xray is not None and not runtime_xray.used_selected_node:
                session_node = None

            if session_node is not None:
                session_node.last_used_at = datetime.now(timezone.utc).isoformat()

            self._set_connection_status(
                "running",
                (
                    f"Подключено: {session_label}"
                    + (
                        " (TUN, xray sidecar)"
                        if tun and singbox_plan is not None and singbox_plan.is_hybrid
                        else " (TUN)" if tun else ""
                    )
                ),
                level="success",
            )
            self._capture_active_session(
                session_node,
                tun=tun,
                core=self._active_core,
                api_port=self._xray_api_port,
                hybrid=bool(singbox_plan is not None and singbox_plan.is_hybrid),
                socks_port=runtime_xray.socks_port if runtime_xray is not None else None,
                http_port=runtime_xray.http_port if runtime_xray is not None else None,
                xray_inbound_tags=runtime_xray.inbound_tags if runtime_xray is not None else ("socks-in", "http-in"),
                sidecar_relay_port=singbox_plan.xray_sidecar.relay_port if singbox_plan and singbox_plan.xray_sidecar else 0,
                protect_ss_port=self._protect_ss_port,
                protect_ss_password=self._protect_ss_password,
                ping_host=(
                    runtime_xray.ping_host if runtime_xray is not None else
                    self._infer_singbox_ping_target(
                        singbox_plan.singbox_config if singbox_plan is not None else {},
                        session_node,
                    )[0]
                ),
                ping_port=(
                    runtime_xray.ping_port if runtime_xray is not None else
                    self._infer_singbox_ping_target(
                        singbox_plan.singbox_config if singbox_plan is not None else {},
                        session_node,
                    )[1]
                ),
            )
            self.save()
            session_mode = "xray-tun" if tun and self._active_core == "xray" else self._active_core
            self._traffic_history.start_session(session_label, session_mode)
            return True
        finally:
            self._connecting = False

    def disconnect_current(self, disable_proxy: bool = True, emit_status: bool = True) -> bool:
        self._disconnecting = True
        try:
            self._cleanup_connection_runtime_state(
                end_traffic_session=True,
                reset_auto_switch_cycle=not self._auto_switch_transitioning,
                reset_auto_switch_cooldown=not self._reconnecting and not self._auto_switch_transitioning,
            )
            active_tun = self._active_session.tun_mode if self._active_session is not None else self.state.settings.tun_mode
            if emit_status and active_tun:
                self.status.emit("info", "Остановка VPN...")
            stopped = self._stop_active_connection_processes(disable_proxy=disable_proxy)
            if stopped:
                self._active_core = "xray"
                self._clear_active_session()
            if emit_status:
                if stopped:
                    self._set_connection_status("idle", "Отключено", level="info")
                else:
                    self._set_connection_status("error", "Не удалось корректно остановить подключение", level="error")
            return stopped
        finally:
            self._disconnecting = False

    def _restart_proxy_core(self, reason: str) -> bool:
        node = self.selected_node
        self._switching = True
        try:
            self._log(f"[proxy-hot-swap] {reason}")
            try:
                runtime_xray = self._build_runtime_xray_config(node, tun_mode=False)
            except ValueError as exc:
                self._set_connection_status("error", str(exc), level="error")
                return False

            session_label = runtime_xray.source_path.name
            if runtime_xray.used_selected_node and node is not None:
                session_label = f"{runtime_xray.source_path.name} / {node.name}"
            self._set_connection_status("starting", f"Переключение на {session_label}...", level="info")
            self._stop_metrics_worker()
            if self.xray.is_running and not self.xray.stop():
                self._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
                return False

            self._xray_api_port = runtime_xray.api_port
            ok = self.xray.start(self.state.settings.xray_path, runtime_xray.config)
            if not ok:
                self._handle_unexpected_disconnect()
                return False

            if self.state.settings.enable_system_proxy:
                if runtime_xray.http_port <= 0 or runtime_xray.socks_port <= 0:
                    self.xray.stop()
                    self._set_connection_status(
                        "error",
                        "В raw xray config нет HTTP/SOCKS inbound портов для включения системного прокси.",
                        level="error",
                    )
                    self._handle_unexpected_disconnect()
                    return False
                try:
                    self.proxy.enable(
                        runtime_xray.http_port,
                        runtime_xray.socks_port,
                        bypass_lan=self._system_proxy_bypass_lan(),
                    )
                except Exception as exc:
                    self.xray.stop()
                    self._set_connection_status(
                        "error",
                        f"Не удалось включить системный прокси: {exc}",
                        level="error",
                    )
                    self._handle_unexpected_disconnect()
                    return False
            else:
                self.proxy.disable(restore_previous=True)

            session_node = node if runtime_xray.used_selected_node else None
            if session_node is not None:
                session_node.last_used_at = datetime.now(timezone.utc).isoformat()
            self._capture_active_session(
                session_node,
                tun=False,
                core="xray",
                api_port=self._xray_api_port,
                socks_port=runtime_xray.socks_port,
                http_port=runtime_xray.http_port,
                xray_inbound_tags=runtime_xray.inbound_tags,
                ping_host=runtime_xray.ping_host,
                ping_port=runtime_xray.ping_port,
            )
            self._set_connection_status("running", f"Переключено: {session_label}", level="success")
            self.save()
            return True
        finally:
            self._switching = False
            _, self.connected = self._refresh_connected_state()
            self.connection_changed.emit(self.connected)
            if self.connected:
                self._start_metrics_worker()
            else:
                self._stop_metrics_worker()

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
            if not self.is_legacy_tun2socks_mode():
                return
            self._request_transition("routing changed")

    def update_settings(self, settings: AppSettings) -> None:
        old_settings = self.state.settings
        old_launch = old_settings.launch_on_startup
        old_tun = old_settings.tun_mode
        old_tun_engine = old_settings.tun_engine
        self.state.settings = settings
        self.settings_changed.emit(self.state.settings)
        self.schedule_save()

        if old_launch != settings.launch_on_startup:
            try:
                set_startup_enabled(APP_NAME, settings.launch_on_startup, build_startup_command())
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
        nodes = self.state.nodes
        if node_ids:
            nodes = [node for node in nodes if node.id in node_ids]
        if not nodes:
            return

        if self._ping_worker and self._ping_worker.isRunning():
            self._ping_worker.cancel()
            self._ping_worker.wait(500)

        self._ping_total = len(nodes)
        self._ping_completed = 0
        self.bulk_task_progress.emit("ping", 0, self._ping_total, False)
        self._ping_worker = PingWorker(nodes)
        self._ping_worker.result.connect(self._on_ping_result)
        self._ping_worker.progress.connect(self._on_ping_progress)
        self._ping_worker.completed.connect(self._on_ping_complete)
        self._ping_worker.start()

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> bool:
        """Запуск теста скорости для указанных нод (или всех, если None)."""
        nodes = self.state.nodes
        if node_ids:
            nodes = [node for node in nodes if node.id in node_ids]
        if not nodes:
            return False

        if self._speed_worker and self._speed_worker.isRunning():
            self.status.emit("info", "Тест скорости уже выполняется. Остановите его перед новым запуском.")
            return False

        from .path_utils import resolve_configured_path
        from .constants import XRAY_PATH_DEFAULT
        resolved = resolve_configured_path(
            self.state.settings.xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        xray_path = str(resolved) if resolved else self.state.settings.xray_path

        self._speed_total = len(nodes)
        self._speed_completed = 0
        self.bulk_task_progress.emit("speed", 0, self._speed_total, False)
        self._speed_worker = SpeedTestWorker(
            nodes,
            xray_path=xray_path,
            routing=self.state.routing,
        )
        self._speed_worker.result.connect(self._on_speed_result)
        self._speed_worker.progress.connect(self._on_speed_progress)
        self._speed_worker.node_progress.connect(self._on_speed_node_progress)
        self._speed_worker.completed.connect(self._on_speed_complete)
        self._speed_worker.start()
        return True

    def cancel_speed_test(self) -> bool:
        worker = self._speed_worker
        if worker is None or not worker.isRunning():
            self.status.emit("info", "Тест скорости сейчас не выполняется")
            return False
        worker.cancel()
        self.status.emit("info", "Останавливаю тест скорости...")
        return True

    def get_fastest_alive_node(self) -> Node | None:
        """Вернуть ноду с наибольшей скоростью среди живых, или лучшую по пингу."""
        alive_nodes = [n for n in self.state.nodes if n.is_alive is True]
        if not alive_nodes:
            # Запасной вариант — любая нода с пингом
            alive_nodes = [n for n in self.state.nodes if n.ping_ms is not None]
        if not alive_nodes:
            return self.selected_node  # запасной — текущая выбранная

        # Предпочитаем ноды с данными о скорости
        with_speed = [n for n in alive_nodes if n.speed_mbps is not None and n.speed_mbps > 0]
        if with_speed:
            return max(with_speed, key=lambda n: n.speed_mbps)

        # Запасной вариант — наименьший пинг
        return min(alive_nodes, key=lambda n: n.ping_ms if n.ping_ms is not None else float('inf'))

    def test_connectivity(self, url: str | None = None) -> None:
        target = (url or "https://www.gstatic.com/generate_204").strip()
        if not target:
            target = "https://www.gstatic.com/generate_204"

        if self._connectivity_worker and self._connectivity_worker.isRunning():
            self.status.emit("info", "Тест подключения уже выполняется")
            return

        http_port = self.get_effective_http_proxy_port() or DEFAULT_HTTP_PORT

        self._connectivity_worker = ConnectivityTestWorker(
            http_port, target, tun_mode=self.state.settings.tun_mode,
        )
        self._connectivity_worker.result.connect(self._on_connectivity_result)
        self._connectivity_worker.start()

    def run_xray_core_update(self, apply_update: bool, silent: bool = False) -> None:
        if self._xray_update_worker and self._xray_update_worker.isRunning():
            if not silent:
                self.status.emit("info", "Обновление Xray уже выполняется")
            return

        if silent and apply_update and self.connected:
            self._log("[core-update] silent auto-update skipped while connected")
            return

        if apply_update and self.connected:
            stopped = self.disconnect_current()
            if not stopped:
                self._reconnect_after_xray_update = False
                if silent:
                    self._log("[core-update] update cancelled: failed to stop active connection")
                else:
                    self.status.emit("error", "Не удалось остановить активное подключение перед обновлением Xray")
                return
            self._reconnect_after_xray_update = True
        else:
            self._reconnect_after_xray_update = False

        self._xray_update_silent = silent
        self._xray_update_worker = XrayCoreUpdateWorker(
            self.state.settings.xray_path,
            self.state.settings.xray_release_channel,
            self.state.settings.xray_update_feed_url,
            apply_update=apply_update,
        )
        self._xray_update_worker.done.connect(self._on_xray_update_worker_done)
        self._xray_update_worker.start()

        if not silent:
            message = "Обновление Xray..." if apply_update else "Проверка обновлений Xray..."
            self.status.emit("info", message)

    def _start_metrics_worker(self) -> None:
        session = self._active_session
        node = self.selected_node
        ping_host = session.ping_host if session is not None else (node.server if node else "")
        ping_port = session.ping_port if session is not None else (node.port if node else 0)
        self._log(f"[metrics] starting worker, active_core={self._active_core}")

        self._stop_metrics_worker()
        if self._active_core == "singbox":
            mode = "singbox"
        elif self._active_session is not None and self._active_session.tun_mode:
            mode = "xray-tun"
        else:
            mode = "xray"
        socks_port, http_port = self.get_effective_proxy_ports()
        inbound_tags = self._active_session.xray_inbound_tags if self._active_session else ()
        self._metrics_worker = LiveMetricsWorker(
            self.state.settings.xray_path,
            self._xray_api_port,
            ping_host=ping_host,
            ping_port=ping_port,
            mode=mode,
            clash_api_port=SINGBOX_CLASH_API_PORT,
            socks_port=socks_port,
            http_port=http_port,
            xray_inbound_tags=list(inbound_tags),
        )
        self._metrics_worker.metrics.connect(self._on_live_metrics)
        self._metrics_worker.start()

    def _stop_metrics_worker(self) -> None:
        if not self._metrics_worker:
            return
        if self._metrics_worker.isRunning():
            self._metrics_worker.stop()
            self._metrics_worker.wait(1200)
        self._metrics_worker = None

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
        was_connected, is_connected = self._refresh_connected_state()
        if not self._switching and was_connected != is_connected:
            self.connection_changed.emit(is_connected)
        if is_connected and not self._switching and not was_connected:
            self._start_metrics_worker()
        elif not is_connected:
            self._stop_metrics_worker()
            if was_connected and not self._switching:
                self.live_metrics_updated.emit({"down_bps": 0.0, "up_bps": 0.0, "latency_ms": None})
                if not self._disconnecting:
                    self._handle_unexpected_disconnect()
        if not is_connected and self._active_core == "xray" and self.state.settings.enable_system_proxy and not self._reconnecting:
            self.proxy.disable(restore_previous=True)

    def _on_ping_result(self, node_id: str, ping_ms: int | None) -> None:
        if self.sender() is not self._ping_worker:
            return
        for node in self.state.nodes:
            if node.id == node_id:
                node.ping_ms = ping_ms
                # Не перезаписываем is_alive=True от speed test результатом ping=None
                if ping_ms is not None or node.is_alive is None:
                    node.is_alive = ping_ms is not None
                ts = datetime.now(timezone.utc).isoformat()
                node.ping_history.append((ts, ping_ms))
                if len(node.ping_history) > 50:
                    node.ping_history = node.ping_history[-50:]
                break
        self.ping_updated.emit(node_id, ping_ms)

    def _on_ping_progress(self, current: int, total: int) -> None:
        if self.sender() is not self._ping_worker:
            return
        self._ping_completed = current
        self.bulk_task_progress.emit("ping", current, total, False)

    def _on_ping_complete(self) -> None:
        if self.sender() is not self._ping_worker:
            return
        self.bulk_task_progress.emit("ping", self._ping_completed, self._ping_total, True)
        self._ping_worker = None
        self.save()

    def _on_speed_result(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        if self.sender() is not self._speed_worker:
            return
        for node in self.state.nodes:
            if node.id == node_id:
                node.speed_mbps = speed_mbps
                # Не перезаписываем is_alive=True от пинга результатом speed=False
                if is_alive or node.is_alive is None:
                    node.is_alive = is_alive
                ts = datetime.now(timezone.utc).isoformat()
                node.speed_history.append((ts, speed_mbps))
                if len(node.speed_history) > 50:
                    node.speed_history = node.speed_history[-50:]
                break
        self.save()
        self.speed_updated.emit(node_id, speed_mbps, is_alive)

    def _on_speed_progress(self, current: int, total: int) -> None:
        if self.sender() is not self._speed_worker:
            return
        self._speed_completed = current
        self.bulk_task_progress.emit("speed", current, total, False)

    def _on_speed_node_progress(self, node_id: str, percent: int) -> None:
        if self.sender() is not self._speed_worker:
            return
        self.speed_progress_updated.emit(node_id, max(0, min(100, int(percent))))

    def _on_speed_complete(self) -> None:
        if self.sender() is not self._speed_worker:
            return
        worker = self._speed_worker
        cancelled = bool(worker.was_cancelled) if worker is not None else False
        completed = worker.completed_nodes if worker is not None else self._speed_completed
        self._speed_completed = completed
        if cancelled:
            self.speed_test_cancelled.emit(completed, self._speed_total)
        self.bulk_task_progress.emit("speed", completed, self._speed_total, True)
        self._speed_worker = None
        if cancelled:
            self.status.emit("info", f"Тест скорости остановлен ({completed}/{self._speed_total})")
        else:
            self.status.emit("success", "Тест скорости завершён")

    def _on_connectivity_result(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        if self.sender() is not self._connectivity_worker:
            return
        self._connectivity_worker = None
        if ok and elapsed_ms is not None:
            text = f"Подключение в порядке: {elapsed_ms} мс"
            self.status.emit("success", text)
            self._log(f"[test] {message} ({elapsed_ms} ms)")
        else:
            self.status.emit("warning", "Тест подключения не пройден")
            self._log(f"[test] {message}")
        self.connectivity_test_done.emit(ok, message, elapsed_ms)

    def _on_live_metrics(self, payload: dict[str, object]) -> None:
        self.live_metrics_updated.emit(payload)
        # Auto-switch check — only reads payload, no extra I/O
        down_bps = float(payload.get("down_bps") or 0.0)
        self._check_auto_switch(down_bps)
        # Update traffic history with process stats
        process_stats = payload.get("process_stats")
        if process_stats:
            stats_dict = {}
            for ps in process_stats:
                stats_dict[ps.exe] = (ps.upload, ps.download, ps.route)
            self._traffic_history.update_session(stats_dict)
            self._traffic_save_counter += 1
            if self._traffic_save_counter >= 15:  # ~30 sec at 2s interval
                self._traffic_history.save_periodic()
                self._traffic_save_counter = 0

    # Require N consecutive high-speed readings to confirm "active download"
    _AUTO_SWITCH_HIGH_TICKS_REQUIRED = 10  # ~10s of sustained traffic above threshold
    # Minimum speed to count as "traffic exists" (1 KB/s) vs idle (0)
    _AUTO_SWITCH_IDLE_BPS = 1024.0

    def _check_auto_switch(self, down_bps: float) -> None:
        """Check if speed is below threshold long enough to trigger node switch.

        CRITICAL: This method MUST NOT perform any I/O — it only reads
        in-memory state from the already-collected metrics payload.

        Trigger conditions (ALL must be met):
        1. auto_switch_enabled = True
        2. Connected, not switching/reconnecting, 2+ nodes
        3. There was sustained traffic (10+ consecutive ticks above threshold)
        4. Speed dropped below threshold for delay_sec continuously
        5. Speed is not zero (zero = idle, not speed drop)
        6. Cooldown since last switch has elapsed
        """
        settings = self.state.settings
        if not settings.auto_switch_enabled:
            return
        if not self.connected or self._switching or self._reconnecting:
            return
        if len(self.state.nodes) < 2:
            return
        if self._auto_switch_exhausted:
            return

        now = time.monotonic()
        threshold_bps = settings.auto_switch_threshold_kbps * 1024.0

        # Speed above threshold — accumulate "active download" evidence
        if down_bps >= threshold_bps:
            self._auto_switch_high_ticks += 1
            if self._auto_switch_high_ticks >= self._AUTO_SWITCH_HIGH_TICKS_REQUIRED:
                self._auto_switch_active_download = True
            self._auto_switch_low_since = 0.0
            return

        # Speed below threshold
        # Not yet confirmed as active download — ignore
        if not self._auto_switch_active_download:
            self._auto_switch_high_ticks = 0
            return

        # Zero traffic = idle browsing, not speed drop — reset timer & high ticks
        if down_bps < self._AUTO_SWITCH_IDLE_BPS:
            self._auto_switch_low_since = 0.0
            self._auto_switch_high_ticks = 0
            self._auto_switch_active_download = False
            return

        # Speed is between IDLE and threshold — genuine speed drop
        # Reset high ticks counter (speed is no longer high)
        self._auto_switch_high_ticks = 0

        # Start tracking low-speed moment
        if self._auto_switch_low_since == 0.0:
            self._auto_switch_low_since = now
            return

        # Check if speed has been low long enough
        low_duration = now - self._auto_switch_low_since
        if low_duration < settings.auto_switch_delay_sec:
            return

        # Check cooldown
        if now - self._auto_switch_last_switch < settings.auto_switch_cooldown_sec:
            return

        max_attempts = max(1, len(self.state.nodes) - 1)
        if self._auto_switch_cycle_attempts >= max_attempts:
            self._auto_switch_exhausted = True
            self._auto_switch_low_since = 0.0
            self._auto_switch_active_download = False
            self.status.emit("warning", "Автопереключение остановлено: все серверы уже проверены")
            self._log("[auto-switch] exhausted all nodes for current session")
            return

        # --- Trigger auto-switch ---
        self._auto_switch_low_since = 0.0
        self._auto_switch_last_switch = now
        self._auto_switch_active_download = False

        next_node = self._get_next_node_for_auto_switch()
        if not next_node:
            return

        self._auto_switch_cycle_attempts += 1
        self._auto_switch_transitioning = True
        self._log(f"[auto-switch] speed {down_bps / 1024:.0f} KB/s < {settings.auto_switch_threshold_kbps} KB/s "
                   f"for {low_duration:.0f}s → switching to {next_node.name}")
        self.auto_switch_triggered.emit(next_node.name)

        # Change selected node and hot-swap
        self.state.selected_node_id = next_node.id
        self.selection_changed.emit(next_node)
        self.save()
        self._desired_connected = True
        self._request_transition("auto-switch: speed drop")

    def _get_next_node_for_auto_switch(self) -> Node | None:
        """Pick next node: prefer alive nodes with best speed, fall back to round-robin."""
        current_id = self.state.selected_node_id
        nodes = self.state.nodes
        if not nodes:
            return None

        # Try alive nodes with speed data (excluding current)
        candidates = [
            n for n in nodes
            if n.id != current_id and n.is_alive is True and n.speed_mbps is not None and n.speed_mbps > 0
        ]
        if candidates:
            return max(candidates, key=lambda n: n.speed_mbps)

        # Fall back to alive nodes by ping
        candidates = [
            n for n in nodes
            if n.id != current_id and n.is_alive is True
        ]
        if candidates:
            return min(candidates, key=lambda n: n.ping_ms if n.ping_ms is not None else float('inf'))

        # Last resort: round-robin to next node
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

    def _on_xray_update_worker_done(self, result: XrayCoreUpdateResult) -> None:
        self._xray_update_worker = None
        self.xray_update_result.emit(result)

        if result.status == "error":
            if not self._xray_update_silent:
                self.status.emit("error", result.message)
            else:
                self._log(f"[core-update] error: {result.message}")
        elif result.status == "updated":
            if not self._xray_update_silent:
                self.status.emit("success", result.message)
            self._log(f"[core-update] {result.message}")
        elif result.status == "available":
            if not self._xray_update_silent:
                self.status.emit("warning", result.message)
            else:
                self._log(f"[core-update] {result.message}")
        elif result.status == "up_to_date":
            if not self._xray_update_silent:
                self.status.emit("info", result.message)
            else:
                self._log(f"[core-update] {result.message}")

        if self._reconnect_after_xray_update:
            self._reconnect_after_xray_update = False
            self._desired_connected = True
            self._request_transition("core update reconnect")

        self._xray_update_silent = False

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
        if not node or session is None:
            self._auto_switch_transitioning = False
            return False

        self._xray_api_port = session.api_port
        self._protect_ss_port = session.protect_ss_port
        self._protect_ss_password = session.protect_ss_password

        # legacy tun2socks mode: restart only xray while the TUN adapter stays up
        if self._active_core == "tun2socks":
            self._switching = True
            try:
                problem = self._prepare_node_for_runtime(node)
                if problem:
                    self._set_connection_status("error", problem, level="error")
                    return False
                self._log(f"[hot-swap] {reason} — restarting xray only, tun2socks stays up")
                self._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
                self.xray.stop()
                config = build_xray_config(
                    node,
                    self.state.routing,
                    self.state.settings,
                    api_port=self._xray_api_port,
                    socks_port=DEFAULT_SOCKS_PORT,
                    http_port=DEFAULT_HTTP_PORT,
                )
                config["log"] = {"loglevel": "error"}
                ok = self.xray.start(self.state.settings.xray_path, config)
                if ok:
                    node.last_used_at = datetime.now(timezone.utc).isoformat()
                    self._capture_active_session(
                        node,
                        tun=True,
                        core="tun2socks",
                        api_port=self._xray_api_port,
                        xray_inbound_tags=("socks-in", "http-in"),
                        ping_host=node.server,
                        ping_port=node.port,
                    )
                    self._set_connection_status("running", f"Переключено: {node.name} (TUN)", level="success")
                    self.save()
                else:
                    self._log("[hot-swap] xray restart failed")
                    self._set_connection_status("error", "Не удалось переключить сервер, подключение остановлено", level="error")
                    self._handle_unexpected_disconnect()
                return ok
            finally:
                self._switching = False
                self._auto_switch_transitioning = False
                _, self.connected = self._refresh_connected_state()
                self.connection_changed.emit(self.connected)
                if self.connected:
                    self._start_metrics_worker()
                else:
                    self._stop_metrics_worker()

        # sing-box raw mode keeps the user config as the source of truth and may
        # switch between native and hybrid planner outcomes, so reconnect.
        return self._reconnect(f"{reason} (sing-box config change)")

    def _reconnect(self, reason: str) -> bool:
        if self._reconnecting:
            return False
        self._reconnecting = True
        self._switching = True
        try:
            self._log(f"[reconnect] {reason}")
            self._set_connection_status("starting", "Переподключение...", level="info")
            stopped = self.disconnect_current(disable_proxy=False, emit_status=False)
            if not stopped:
                self._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
                if self.state.settings.enable_system_proxy:
                    self.proxy.disable(restore_previous=True)
                return False

            ok = self.connect_selected(allow_during_reconnect=True)
            if not ok and self.state.settings.enable_system_proxy:
                self.proxy.disable(restore_previous=True)
            return ok
        finally:
            self._reconnecting = False
            self._switching = False
            self._auto_switch_transitioning = False
            _, self.connected = self._refresh_connected_state()
            self.connection_changed.emit(self.connected)
            if self.connected:
                self._start_metrics_worker()
            else:
                self._stop_metrics_worker()

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


def _is_admin() -> bool:
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
