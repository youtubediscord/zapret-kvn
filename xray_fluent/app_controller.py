from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .country_flags import CountryResolver, detect_country
from .config_builder import build_xray_config
from .singbox_config_builder import build_singbox_config, build_xray_hybrid_config, needs_xray_hybrid, TunConfigBundle
from .connectivity_test import ConnectivityTestWorker
from .constants import APP_NAME, LOG_DIR, ROUTING_MODES, SINGBOX_CLASH_API_PORT, DEFAULT_XRAY_STATS_API_PORT
from .diagnostics import export_diagnostics
from .link_parser import parse_links_text
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
    protect_ss_port: int
    protect_ss_password: str


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

    def _transition_signature(
        self,
        node: Node | None = None,
        settings: AppSettings | None = None,
        routing: RoutingSettings | None = None,
    ) -> str:
        settings = settings or self.state.settings
        routing = routing or self.state.routing
        node = node or self.selected_node
        return self._signature(
            {
                "node_id": node.id if node else None,
                "tun_mode": bool(settings.tun_mode),
                "tun_engine": str(settings.tun_engine),
                "proxy_enabled": bool(settings.enable_system_proxy),
                "proxy_bypass_lan": bool(routing.bypass_lan),
                "socks_port": int(settings.socks_port),
                "http_port": int(settings.http_port),
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
        return self._signature(
            {
                "node_id": node.id if node else None,
                "tun_mode": bool(settings.tun_mode),
                "tun_engine": str(settings.tun_engine),
                "socks_port": int(settings.socks_port),
                "http_port": int(settings.http_port),
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
        if settings.tun_engine == "tun2socks":
            return self._signature(
                {
                    "mode": "tun2socks",
                    "server": node.server if node else "",
                    "socks_port": int(settings.socks_port),
                }
            )
        if node is not None and needs_xray_hybrid(node):
            return self._signature(
                {
                    "mode": "singbox-hybrid",
                    "routing": routing.to_dict(),
                    "xray_path": str(settings.xray_path),
                    "singbox_path": str(settings.singbox_path),
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
        node: Node,
        *,
        tun: bool,
        core: str,
        api_port: int,
        protect_ss_port: int = 0,
        protect_ss_password: str = "",
    ) -> None:
        settings = self.state.settings
        routing = self.state.routing
        hybrid = bool(tun and core == "singbox" and needs_xray_hybrid(node))
        self._active_session = ActiveSessionSnapshot(
            node_id=node.id,
            node_server=node.server,
            active_core=core,
            tun_mode=bool(tun),
            tun_engine=str(settings.tun_engine),
            proxy_enabled=bool(settings.enable_system_proxy),
            proxy_bypass_lan=bool(routing.bypass_lan),
            xray_path=str(settings.xray_path),
            singbox_path=str(settings.singbox_path),
            socks_port=int(settings.socks_port),
            http_port=int(settings.http_port),
            routing_signature=self._routing_signature(routing),
            transition_signature=self._transition_signature(node, settings, routing),
            xray_layer_signature=self._xray_layer_signature(node, settings, routing),
            tun_layer_signature=self._tun_layer_signature(node, settings, routing),
            hybrid=hybrid,
            api_port=int(api_port),
            protect_ss_port=int(protect_ss_port),
            protect_ss_password=str(protect_ss_password),
        )
        self._blocked_transition_signature = ""

    def _clear_active_session(self) -> None:
        self._active_session = None

    def _apply_proxy_runtime_change(self) -> bool:
        settings = self.state.settings
        routing = self.state.routing
        try:
            if settings.enable_system_proxy:
                self.proxy.enable(
                    settings.http_port,
                    settings.socks_port,
                    bypass_lan=routing.bypass_lan,
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
        if node is not None and self.connected:
            self._capture_active_session(
                node,
                tun=False,
                core="xray",
                api_port=self._active_session.api_port if self._active_session else self._xray_api_port,
            )
        return True

    def _needs_transition(self) -> bool:
        if self._desired_connected:
            node = self.selected_node
            if node is None or self.locked:
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
            or session.proxy_bypass_lan != bool(self.state.routing.bypass_lan)
        )

    def _can_proxy_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        if session.active_core != "xray" or session.tun_mode or settings.tun_mode:
            return False
        if session.socks_port != int(settings.socks_port) or session.http_port != int(settings.http_port):
            return False
        return session.xray_layer_signature != self._xray_layer_signature()

    def _can_tun_hot_swap(self, session: ActiveSessionSnapshot) -> bool:
        settings = self.state.settings
        node = self.selected_node
        if node is None or not settings.tun_mode or not session.tun_mode:
            return False
        if session.tun_engine != str(settings.tun_engine):
            return False
        if session.active_core == "tun2socks":
            if settings.tun_engine != "tun2socks":
                return False
            return session.tun_layer_signature == self._tun_layer_signature(node, settings, self.state.routing)

        if session.active_core != "singbox" or settings.tun_engine != "singbox":
            return False
        if not session.hybrid or not needs_xray_hybrid(node):
            return False
        if session.protect_ss_port <= 0 or not session.protect_ss_password:
            return False
        return session.tun_layer_signature == self._tun_layer_signature(node, settings, self.state.routing)

    def _compute_transition_action(self) -> str | None:
        if not self._desired_connected:
            return "disconnect" if self.connected else None

        node = self.selected_node
        if node is None:
            return None
        if self.locked:
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

    def export_node_outbound_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        return json.dumps(node.outbound, ensure_ascii=True, indent=2)

    def export_runtime_config_json(self, node_id: str | None = None) -> str | None:
        node = self._get_node_by_id(node_id) if node_id else self.selected_node
        if not node:
            return None
        cfg = build_xray_config(node, self.state.routing, self.state.settings)
        return json.dumps(cfg, ensure_ascii=True, indent=2)

    def import_nodes_from_text(self, text: str) -> tuple[int, list[str]]:
        nodes, errors = parse_links_text(text)
        if not nodes:
            return 0, errors

        existing_links = {node.link for node in self.state.nodes}
        max_order = max((n.sort_order for n in self.state.nodes), default=0)
        first_new_id: str | None = None
        added = 0
        for node in nodes:
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
        node = self.selected_node
        if self._active_core == "singbox":
            hybrid_needed = needs_xray_hybrid(node) if node is not None else False
            return self.singbox.is_running and (self.xray.is_running if hybrid_needed else True)
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
            if not node:
                self._set_connection_status("error", "Сначала выберите сервер.", level="warning")
                return False

            self._reset_auto_switch_state(
                reset_cooldown=not self._auto_switch_transitioning,
                reset_cycle=not self._auto_switch_transitioning,
            )

            try:
                self._xray_api_port = _find_free_api_port(
                    excluded={self.state.settings.socks_port, self.state.settings.http_port},
                )
            except RuntimeError:
                self._set_connection_status("error", "Не удалось найти свободный порт для API Xray", level="error")
                return False

            prev_active_core = self._active_core
            tun = self.state.settings.tun_mode

            if tun:
                self._log(f"[tun] attempting TUN connect, admin={_is_admin()}")
                self._set_connection_status("starting", f"Запуск VPN: {node.name}...", level="info")

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
                    # --- sing-box TUN (experimental, supports process routing) ---
                    self._active_core = "singbox"  # Set early so metrics worker gets correct mode
                    bundle = build_singbox_config(node, self.state.routing, self.state.settings, api_port=self._xray_api_port)

                    if bundle.is_hybrid:
                        self._set_connection_status("starting", "Запуск Xray (dialerProxy)...", level="info")
                        xray_cfg = bundle.xray_config
                        xray_cfg["log"] = {"loglevel": "error"}
                        xray_ok = self.xray.start(self.state.settings.xray_path, xray_cfg)
                        if not xray_ok:
                            self._log("[tun] xray start failed")
                            self._active_core = prev_active_core
                            return False
                        self._set_connection_status("starting", "Xray запущен. Создание TUN адаптера...", level="info")

                    self._log(f"[tun] starting sing-box TUN (hybrid={bundle.is_hybrid})")
                    sb_ok = self.singbox.start(self.state.settings.singbox_path, bundle.singbox_config)
                    self._log(f"[tun] sing-box start result: {sb_ok}")
                    if not sb_ok:
                        if bundle.is_hybrid:
                            self.xray.stop()
                        self._set_connection_status(
                            "error",
                            "Не удалось создать TUN адаптер. Проверьте наличие wintun.dll в core/.",
                            level="error",
                        )
                        self._active_core = prev_active_core
                        return False
                    self._protect_ss_port = bundle.protect_port
                    self._protect_ss_password = bundle.protect_password
                else:
                    # --- tun2socks TUN (stable, default) ---
                    self._active_core = "tun2socks"
                    config = build_xray_config(node, self.state.routing, self.state.settings, api_port=self._xray_api_port)
                    config["log"] = {"loglevel": "error"}
                    xray_ok = self.xray.start(self.state.settings.xray_path, config)
                    if not xray_ok:
                        self._log("[tun] xray start failed")
                        self._active_core = prev_active_core
                        return False
                    self._set_connection_status("starting", "Xray запущен. Создание TUN адаптера...", level="info")

                    socks_port = self.state.settings.socks_port
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
                self._active_core = "xray"
                self._set_connection_status("starting", f"Запуск прокси: {node.name}...", level="info")
                config = build_xray_config(node, self.state.routing, self.state.settings, api_port=self._xray_api_port)
                ok = self.xray.start(self.state.settings.xray_path, config)
                if not ok:
                    self._active_core = prev_active_core
                    return False

                if self.state.settings.enable_system_proxy:
                    try:
                        self.proxy.enable(
                            self.state.settings.http_port,
                            self.state.settings.socks_port,
                            bypass_lan=self.state.routing.bypass_lan,
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

            node.last_used_at = datetime.now(timezone.utc).isoformat()
            self._set_connection_status("running", f"Подключено: {node.name}" + (" (TUN)" if tun else ""), level="success")
            self._capture_active_session(
                node,
                tun=tun,
                core=self._active_core,
                api_port=self._xray_api_port,
                protect_ss_port=self._protect_ss_port,
                protect_ss_password=self._protect_ss_password,
            )
            self.save()
            node_name = node.name if node else "unknown"
            self._traffic_history.start_session(node_name, self._active_core)
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
            if emit_status and self._active_core in ("singbox", "tun2socks"):
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
        if node is None:
            return False

        self._switching = True
        try:
            self._log(f"[proxy-hot-swap] {reason}")
            self._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
            self._stop_metrics_worker()
            if self.xray.is_running and not self.xray.stop():
                self._set_connection_status("error", "Не удалось остановить предыдущий процесс Xray", level="error")
                return False

            config = build_xray_config(node, self.state.routing, self.state.settings, api_port=self._xray_api_port)
            ok = self.xray.start(self.state.settings.xray_path, config)
            if not ok:
                self._handle_unexpected_disconnect()
                return False

            if self.state.settings.enable_system_proxy:
                try:
                    self.proxy.enable(
                        self.state.settings.http_port,
                        self.state.settings.socks_port,
                        bypass_lan=self.state.routing.bypass_lan,
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

            node.last_used_at = datetime.now(timezone.utc).isoformat()
            self._capture_active_session(
                node,
                tun=False,
                core="xray",
                api_port=self._xray_api_port,
            )
            self._set_connection_status("running", f"Переключено: {node.name}", level="success")
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
            self._request_transition("routing changed")

    def update_settings(self, settings: AppSettings) -> None:
        old_settings = self.state.settings
        old_launch = old_settings.launch_on_startup
        old_tun = old_settings.tun_mode
        old_tun_engine = old_settings.tun_engine
        ports_changed = (
            old_settings.socks_port != settings.socks_port
            or old_settings.http_port != settings.http_port
        )
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
            if ports_changed:
                self._desired_connected = True
                self._request_transition("proxy ports changed")
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

    def speed_test_nodes(self, node_ids: set[str] | None = None) -> None:
        """Запуск теста скорости для указанных нод (или всех, если None)."""
        nodes = self.state.nodes
        if node_ids:
            nodes = [node for node in nodes if node.id in node_ids]
        if not nodes:
            return

        if self._speed_worker and self._speed_worker.isRunning():
            self._speed_worker.cancel()
            self._speed_worker.wait(3000)

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

        self._connectivity_worker = ConnectivityTestWorker(
            self.state.settings.http_port, target, tun_mode=self.state.settings.tun_mode,
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
        node = self.selected_node
        ping_host = node.server if node else ""
        ping_port = node.port if node else 0
        self._log(f"[metrics] starting worker, active_core={self._active_core}")

        self._stop_metrics_worker()
        mode = "singbox" if self._active_core == "singbox" else "xray"
        self._metrics_worker = LiveMetricsWorker(
            self.state.settings.xray_path,
            self._xray_api_port or DEFAULT_XRAY_STATS_API_PORT,
            ping_host=ping_host,
            ping_port=ping_port,
            mode=mode,
            clash_api_port=SINGBOX_CLASH_API_PORT,
            socks_port=self.state.settings.socks_port,
            http_port=self.state.settings.http_port,
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
        if self.state.settings.auto_connect_last and self.selected_node is not None and not self.locked:
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
        if self._active_core in ("singbox", "tun2socks") and "accepted" in line:
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
        self.bulk_task_progress.emit("speed", self._speed_completed, self._speed_total, True)
        self._speed_worker = None
        self.status.emit("success", "Тест скорости завершён")
        self.save()

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
        if self._active_core in ("singbox", "tun2socks") and self.state.settings.tun_mode:
            self._log("[network] ignoring change in TUN mode")
            return
        if self.connected and self.state.settings.reconnect_on_network_change:
            self._desired_connected = True
            self._request_transition("network changed")

    def _hot_swap_node(self, reason: str) -> bool:
        """Switch node in TUN mode. Restarts only xray; TUN adapter stays alive."""
        node = self.selected_node
        session = self._active_session
        if not node or session is None:
            self._auto_switch_transitioning = False
            return False

        self._xray_api_port = session.api_port
        self._protect_ss_port = session.protect_ss_port
        self._protect_ss_password = session.protect_ss_password

        # tun2socks mode: always hot-swap xray only
        if self._active_core == "tun2socks":
            self._switching = True
            try:
                self._log(f"[hot-swap] {reason} — restarting xray only, tun2socks stays up")
                self._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
                self.xray.stop()
                config = build_xray_config(node, self.state.routing, self.state.settings, api_port=self._xray_api_port)
                config["log"] = {"loglevel": "error"}
                ok = self.xray.start(self.state.settings.xray_path, config)
                if ok:
                    node.last_used_at = datetime.now(timezone.utc).isoformat()
                    self._capture_active_session(
                        node,
                        tun=True,
                        core="tun2socks",
                        api_port=self._xray_api_port,
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

        # sing-box mode
        hybrid_now = self.xray.is_running
        hybrid_next = needs_xray_hybrid(node)

        if hybrid_now != hybrid_next:
            return self._reconnect(f"{reason} (mode change)")

        if hybrid_next:
            # Hybrid: restart only xray, sing-box TUN stays alive
            self._switching = True
            try:
                self._log(f"[hot-swap] {reason} — restarting xray only, sing-box TUN stays up")
                self._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
                self.xray.stop()
                xray_cfg = build_xray_hybrid_config(
                    node,
                    self.state.routing,
                    self.state.settings,
                    session.protect_ss_port,
                    session.protect_ss_password,
                    api_port=session.api_port,
                )
                xray_cfg["log"] = {"loglevel": "error"}
                ok = self.xray.start(self.state.settings.xray_path, xray_cfg)
                if ok:
                    node.last_used_at = datetime.now(timezone.utc).isoformat()
                    self._capture_active_session(
                        node,
                        tun=True,
                        core="singbox",
                        api_port=session.api_port,
                        protect_ss_port=session.protect_ss_port,
                        protect_ss_password=session.protect_ss_password,
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
        else:
            # Native: sing-box holds the outbound, must do full reconnect
            return self._reconnect(f"{reason} (native mode)")

        return False

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
