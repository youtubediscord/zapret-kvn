from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QAction, QActionGroup, QCloseEvent, QGuiApplication, QIcon
from PyQt6.QtWidgets import QApplication, QDialog, QFileDialog, QMenu, QSystemTrayIcon
from qfluentwidgets import (
    FluentIcon as FIF,
    FluentWindow,
    InfoBar,
    InfoBarIcon,
    InfoBarPosition,
    NavigationItemPosition,
    Theme,
    setTheme,
    setThemeColor,
)

from ..app_controller import AppController
from ..storage import PassphraseRequired
from ..constants import APP_NAME, APP_VERSION, LOG_DIR
from ..models import AppSettings, Node, RoutingSettings
from ..app_updater import AppUpdate, UpdateChecker, UpdateDownloader
from ..engines.xray import XrayCoreUpdateResult
from .bulk_edit_dialog import BulkEditDialog
from .dashboard_page import DashboardPage
from .lock_dialog import PasswordDialog
from .logs_page import LogsPage
from .node_edit_dialog import NodeEditDialog
from .nodes_page import NodesPage
from .configs_page import ConfigsPage
from .settings_page import SettingsPage
from .about_page import AboutPage
from .history_page import HistoryPage
from .updates_page import UpdatesPage
from .zapret_page import ZapretPage


class MainWindow(FluentWindow):
    def __init__(self, defer_init: bool = False):
        super().__init__()
        self._quitting = False
        self._tray_notified = False
        self._initialized = False
        self._bulk_task_tip: InfoBar | None = None
        self._bulk_task_type: str | None = None
        self._speed_test_was_cancelled = False
        self._tray_available = QSystemTrayIcon.isSystemTrayAvailable()
        self._deferred_dashboard_metrics: tuple[float, float, int | None] | None = None
        self._deferred_process_stats: list | None = None
        self._has_deferred_process_stats = False
        self._geometry_persistence_ready = False
        self._zapret_autostart_done = False
        self._zapret_autostart_scheduled = False
        self.tray: QSystemTrayIcon | None = None
        self.tray_show_action: QAction | None = None
        self.tray_connect_action: QAction | None = None
        self.tray_next_action: QAction | None = None
        self.tray_quit_action: QAction | None = None
        self.tray_mode_menu: QMenu | None = None
        self.tray_mode_group: QActionGroup | None = None
        self.tray_mode_global: QAction | None = None
        self.tray_mode_rule: QAction | None = None
        self.tray_mode_direct: QAction | None = None

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(":/qfluentwidgets/images/logo.png"))
        self.resize(1280, 720)

        if not defer_init:
            self.initialize()

    def initialize(self) -> None:
        if self._initialized:
            return

        self._initialized = True
        self.controller = AppController(self)
        self.dashboard_page = DashboardPage(self)
        self.nodes_page = NodesPage(self)
        self.configs_page = ConfigsPage(self)
        self.zapret_page = ZapretPage(self)
        self.logs_page = LogsPage(self)
        self.settings_page = SettingsPage(self)
        self.updates_page = UpdatesPage(self)
        self.history_page = HistoryPage(self)
        self.about_page = AboutPage(self)

        self._create_navigation()
        self._create_tray()
        self._connect_signals()
        self._init_window()

        loaded = self._load_with_passphrase()
        if loaded:
            self._load_config_editor_documents()

        unlocked = True
        if loaded and self.controller.state.security.enabled:
            self.controller.locked = True
            unlocked = self._ensure_unlocked(startup=True)

        if loaded and unlocked:
            self.history_page.set_storage(self.controller.traffic_history)
            self.controller.auto_connect_if_needed()

        self._consume_update_error_log()

        # Set Xray version on updates page
        from ..engines.xray import get_xray_version
        xv = get_xray_version(self.controller.state.settings.xray_path)
        self.updates_page.set_xray_version(xv or "")

        if self.controller.state.settings.check_updates:
            QTimer.singleShot(2500, lambda: self._check_updates(silent=True))

        if self.controller.state.settings.xray_auto_update:
            QTimer.singleShot(4500, lambda: self.controller.run_xray_core_update(True, silent=True))

        self._init_zapret_page()

    def _create_navigation(self) -> None:
        self.navigationInterface.setMinimumExpandWidth(700)
        self.navigationInterface.setExpandWidth(200)
        self.addSubInterface(self.dashboard_page, FIF.SPEED_HIGH, "Панель")
        self.addSubInterface(self.nodes_page, FIF.LINK, "Серверы")
        self.addSubInterface(self.configs_page, FIF.CODE, "Конфиги")
        self.addSubInterface(self.zapret_page, FIF.COMMAND_PROMPT, "Zapret")
        self.addSubInterface(self.logs_page, FIF.DOCUMENT, "Логи")
        self.addSubInterface(self.history_page, FIF.HISTORY, "История")
        self.addSubInterface(self.about_page, FIF.INFO, "О проекте", NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.updates_page, FIF.UPDATE, "Обновления", NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FIF.SETTING, "Настройки", NavigationItemPosition.BOTTOM)

    def _create_tray(self) -> None:
        if not self._tray_available:
            return

        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(QIcon(":/qfluentwidgets/images/logo.png"))
        self.tray.setToolTip(APP_NAME)

        menu = QMenu()
        self.tray_show_action = QAction("Показать", self)
        self.tray_connect_action = QAction("Подключить", self)
        self.tray_next_action = QAction("Следующий сервер", self)
        self.tray_quit_action = QAction("Выход", self)

        self.tray_mode_menu = QMenu("Режим", menu)
        self.tray_mode_group = QActionGroup(self)
        self.tray_mode_group.setExclusive(True)
        self.tray_mode_global = QAction("Глобальный", self)
        self.tray_mode_global.setCheckable(True)
        self.tray_mode_rule = QAction("По правилам", self)
        self.tray_mode_rule.setCheckable(True)
        self.tray_mode_direct = QAction("Прямой", self)
        self.tray_mode_direct.setCheckable(True)

        self.tray_mode_group.addAction(self.tray_mode_global)
        self.tray_mode_group.addAction(self.tray_mode_rule)
        self.tray_mode_group.addAction(self.tray_mode_direct)

        self.tray_mode_menu.addAction(self.tray_mode_global)
        self.tray_mode_menu.addAction(self.tray_mode_rule)
        self.tray_mode_menu.addAction(self.tray_mode_direct)

        menu.addAction(self.tray_show_action)
        menu.addAction(self.tray_connect_action)
        menu.addAction(self.tray_next_action)
        menu.addMenu(self.tray_mode_menu)
        menu.addSeparator()
        menu.addAction(self.tray_quit_action)

        self.tray.setContextMenu(menu)
        self.tray.show()

        self.tray.activated.connect(self._on_tray_activated)
        self.tray_show_action.triggered.connect(self._toggle_window_visible)
        self.tray_connect_action.triggered.connect(self.controller.toggle_connection)
        self.tray_next_action.triggered.connect(self.controller.switch_next_node)
        self.tray_quit_action.triggered.connect(self._quit_app)
        self.tray_mode_global.triggered.connect(lambda: self._set_mode_from_tray("global"))
        self.tray_mode_rule.triggered.connect(lambda: self._set_mode_from_tray("rule"))
        self.tray_mode_direct.triggered.connect(lambda: self._set_mode_from_tray("direct"))

    def _connect_signals(self) -> None:
        self.dashboard_page.mode_changed.connect(self._set_mode_only)
        self.dashboard_page.toggle_connection_requested.connect(self.controller.toggle_connection)
        self.dashboard_page.tun_toggled.connect(self._on_dashboard_tun_toggled)
        self.dashboard_page.proxy_toggled.connect(self._on_dashboard_proxy_toggled)
        self.dashboard_page.node_selected.connect(self.controller.set_selected_node)

        self.nodes_page.import_clipboard_requested.connect(self._import_nodes_from_clipboard)
        self.nodes_page.delete_requested.connect(self.controller.remove_nodes)
        self.nodes_page.reorder_requested.connect(self.controller.reorder_nodes)
        self.nodes_page.selected_node_changed.connect(self.controller.set_selected_node)
        self.nodes_page.ping_requested.connect(self._ping_requested)
        self.nodes_page.export_outbound_json_requested.connect(self._export_outbound_json)
        self.nodes_page.export_runtime_json_requested.connect(self._export_runtime_json)
        self.nodes_page.edit_node_requested.connect(self._on_edit_node)
        self.nodes_page.bulk_edit_requested.connect(self._on_bulk_edit_nodes)

        self.configs_page.open_requested.connect(self._open_core_config)
        self.configs_page.reset_requested.connect(self._reset_core_config_to_template)
        self.configs_page.save_requested.connect(self._save_core_config)
        self.configs_page.validate_requested.connect(self._validate_core_config)
        self.configs_page.apply_requested.connect(self._apply_core_config)

        self.zapret_page.start_requested.connect(self._on_zapret_start)
        self.zapret_page.stop_requested.connect(self._on_zapret_stop)
        self.zapret_page.autostart_changed.connect(self._on_zapret_autostart_changed)
        self.controller.zapret.started.connect(self._on_zapret_started)
        self.controller.zapret.stopped.connect(self._on_zapret_stopped)
        self.controller.zapret.error.connect(self._on_zapret_error)
        self.controller.zapret.log_line.connect(self.logs_page.append_line)

        self.logs_page.clear_requested.connect(self._clear_logs_view)
        self.logs_page.export_diag_requested.connect(self._export_diagnostics)

        self.settings_page.save_requested.connect(self.controller.update_settings)
        self.settings_page.auto_lock_minutes_changed.connect(self._update_auto_lock_minutes)
        self.settings_page.set_password_requested.connect(self._set_password)
        self.settings_page.disable_password_requested.connect(self.controller.disable_master_password)
        self.settings_page.lock_now_requested.connect(self.controller.lock)
        self.updates_page.check_app_requested.connect(self._check_updates)
        self.updates_page.check_xray_requested.connect(self._check_xray_updates)
        self.updates_page.update_xray_requested.connect(self._update_xray_core)
        self.settings_page.export_backup_requested.connect(self._export_backup)
        self.settings_page.import_backup_requested.connect(self._import_backup)
        self.settings_page.set_encryption_requested.connect(self._set_encryption)
        self.settings_page.disable_encryption_requested.connect(self._disable_encryption)

        # Тест скорости
        self.nodes_page.speed_test_requested.connect(self._speed_test_requested)
        self.nodes_page.cancel_speed_test_requested.connect(self._cancel_speed_test_requested)
        self.controller.speed_updated.connect(self._on_speed_updated)
        self.controller.speed_test_cancelled.connect(self._on_speed_test_cancelled)

        self.controller.nodes_changed.connect(self._on_nodes_changed)
        self.controller.selection_changed.connect(self._on_selection_changed)
        self.controller.connection_changed.connect(self._on_connection_changed)
        self.controller.connection_status_changed.connect(self.dashboard_page.set_runtime_status)
        self.controller.routing_changed.connect(self._on_routing_changed)
        self.controller.settings_changed.connect(self._on_settings_changed)
        self.controller.log_line.connect(self.logs_page.append_line)
        self.controller.status.connect(self._show_status)
        self.controller.bulk_task_progress.connect(self._on_bulk_task_progress)
        self.controller.ping_updated.connect(self._on_ping_updated)
        self.controller.speed_progress_updated.connect(self._on_speed_progress_updated)
        self.controller.connectivity_test_done.connect(self._on_connectivity_test_done)
        self.controller.live_metrics_updated.connect(self._on_live_metrics_updated)
        self.controller.xray_update_result.connect(self._on_xray_update_result)
        self.controller.lock_state_changed.connect(self._on_lock_state_changed)
        self.controller.auto_switch_triggered.connect(self._on_auto_switch)
        self.controller.transition_state_changed.connect(self._on_transition_state_changed)
        self.stackedWidget.currentChanged.connect(self._on_current_interface_changed)

    def _init_window(self) -> None:
        self.setMinimumSize(600, 450)
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(":/qfluentwidgets/images/logo.png"))
        self._apply_window_geometry(self.controller.state.settings)

    def _apply_window_geometry(self, settings: AppSettings) -> None:
        width = max(self.minimumWidth(), int(settings.window_width or 1000))
        height = max(self.minimumHeight(), int(settings.window_height or 720))
        self.resize(width, height)
        if settings.window_x >= 0 and settings.window_y >= 0:
            if self._is_position_on_screen(settings.window_x, settings.window_y):
                self.move(settings.window_x, settings.window_y)

    @staticmethod
    def _is_position_on_screen(x: int, y: int) -> bool:
        for screen in QGuiApplication.screens():
            if screen.availableGeometry().contains(x, y):
                return True
        return False

    def _on_nodes_changed(self, nodes: list[Node]) -> None:
        selected_id = self.controller.state.selected_node_id
        self.nodes_page.set_nodes(nodes, selected_id)
        self.dashboard_page.set_nodes(nodes, selected_id)
        self._refresh_tray_tooltip()

    def _on_selection_changed(self, node: Node | None) -> None:
        self.dashboard_page.set_selected_node(node)
        if node:
            self.dashboard_page.set_selected_latency(node.ping_ms)
        else:
            self.dashboard_page.set_selected_latency(None)
        self._refresh_tray_tooltip()

    def _on_connection_changed(self, connected: bool) -> None:
        self.dashboard_page.set_connection(connected)
        if not connected:
            self._deferred_dashboard_metrics = None
            self._deferred_process_stats = None
            self._has_deferred_process_stats = False
        if self.tray_connect_action is not None:
            self.tray_connect_action.setText("Отключить" if connected else "Подключить")
        self._refresh_tray_tooltip()

    def _on_transition_state_changed(self, busy: bool, _message: str) -> None:
        self.dashboard_page.set_transition_busy(busy)
        if self.tray_connect_action is not None:
            self.tray_connect_action.setEnabled(not busy)

    def _on_routing_changed(self, routing: RoutingSettings) -> None:
        self.dashboard_page.set_routing_snapshot(routing)
        if self.tray_mode_global is not None:
            self.tray_mode_global.setChecked(routing.mode == "global")
        if self.tray_mode_rule is not None:
            self.tray_mode_rule.setChecked(routing.mode == "rule")
        if self.tray_mode_direct is not None:
            self.tray_mode_direct.setChecked(routing.mode == "direct")

    def _on_settings_changed(self, settings: AppSettings) -> None:
        self.settings_page.set_values(settings, self.controller.state.security)
        self.settings_page.set_encryption_active(self.controller.is_data_encrypted())
        self.dashboard_page.set_settings_snapshot(settings)
        self._apply_window_geometry(settings)
        self._apply_theme(settings.theme, settings.accent_color)
        routing_controls_enabled = bool(settings.tun_mode and settings.tun_engine == "tun2socks")
        for action in (self.tray_mode_global, self.tray_mode_rule, self.tray_mode_direct):
            if action is not None:
                action.setEnabled(routing_controls_enabled)
        self._refresh_tray_tooltip()

    def _on_ping_updated(self, node_id: str, ping_ms: int | None) -> None:
        self.nodes_page.update_ping(node_id, ping_ms)
        self.nodes_page.refresh_detail()
        node = self.controller.selected_node
        if node and node.id == node_id:
            self.dashboard_page.set_selected_latency(ping_ms)

    def _on_live_metrics_updated(self, payload: dict[str, object]) -> None:
        down_bps = float(payload.get("down_bps") or 0.0)
        up_bps = float(payload.get("up_bps") or 0.0)
        latency = payload.get("latency_ms")
        latency_ms = int(latency) if isinstance(latency, int) else None
        process_stats = payload.get("process_stats")
        if not self._is_dashboard_active():
            self._deferred_dashboard_metrics = (down_bps, up_bps, latency_ms)
            if process_stats is not None:
                self._deferred_process_stats = list(process_stats)
                self._has_deferred_process_stats = True
            return

        self.dashboard_page.set_live_metrics(down_bps, up_bps, latency_ms)
        if process_stats is not None:
            self.dashboard_page.set_process_stats(process_stats)

    def _is_dashboard_active(self) -> bool:
        return self.stackedWidget.currentWidget() is self.dashboard_page

    def _on_current_interface_changed(self, _index: int) -> None:
        if not self._is_dashboard_active():
            return
        if self._deferred_dashboard_metrics is not None:
            down_bps, up_bps, latency_ms = self._deferred_dashboard_metrics
            self.dashboard_page.set_live_metrics(down_bps, up_bps, latency_ms)
            self._deferred_dashboard_metrics = None
        if self._has_deferred_process_stats:
            self.dashboard_page.set_process_stats(self._deferred_process_stats or [])
            self._deferred_process_stats = None
            self._has_deferred_process_stats = False

    def _on_xray_update_result(self, result: XrayCoreUpdateResult) -> None:
        self.logs_page.append_line(f"[core-update] {result.status}: {result.message}")
        if result.status == "error":
            self.updates_page.set_xray_error(result.message)
        elif result.status in {"updated", "up_to_date"}:
            self.updates_page.set_xray_success(result.message)
        else:
            self.updates_page.set_xray_status(result.message)

        if result.updated:
            self.updates_page.set_xray_version(result.latest_version)

    def _on_connectivity_test_done(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        if ok and elapsed_ms is not None:
            self.logs_page.append_line(f"[test] ok {elapsed_ms} ms | {message}")
        else:
            self.logs_page.append_line(f"[test] fail | {message}")

    def _on_lock_state_changed(self, locked: bool) -> None:
        if locked:
            self._show_status("warning", "Приложение заблокировано")
            self._ensure_unlocked(startup=False)

    def _on_auto_switch(self, node_name: str) -> None:
        InfoBar.warning(
            "Авто-переключение",
            f"Скорость упала. Переключение на {node_name}...",
            position=InfoBarPosition.TOP_RIGHT,
            duration=30000,
            parent=self,
        )

    def _on_bulk_task_progress(self, task: str, current: int, total: int, completed: bool) -> None:
        task = task.strip().lower()
        if task not in {"ping", "speed"}:
            return

        total = max(1, total)
        current = max(0, min(current, total))
        title = "Пинг серверов" if task == "ping" else "Тест скорости"

        if completed:
            if task == "ping":
                self.nodes_page.finish_ping_activity()
            else:
                self.nodes_page.finish_speed_activity()
            if self._bulk_task_tip and self._bulk_task_type == task:
                if task == "speed" and self._speed_test_was_cancelled:
                    self._set_bulk_task_tip_content(f"Остановлено {current}/{total}")
                    self._speed_test_was_cancelled = False
                else:
                    self._set_bulk_task_tip_content(f"Завершено {current}/{total}")
                QTimer.singleShot(1000, self._clear_bulk_task_tip)
            return

        content = f"{current}/{total}"

        if self._bulk_task_tip is None or self._bulk_task_type != task:
            self._clear_bulk_task_tip()
            tip = InfoBar(
                icon=InfoBarIcon.INFORMATION,
                title=title,
                content=content,
                isClosable=True,
                duration=-1,
                position=InfoBarPosition.TOP_RIGHT,
                parent=self,
            )
            tip.setMinimumWidth(220)
            tip.closedSignal.connect(self._on_bulk_task_tip_closed)
            tip.show()
            self._bulk_task_tip = tip
            self._bulk_task_type = task
            return

        self._set_bulk_task_tip_content(content)

    def _on_bulk_task_tip_closed(self) -> None:
        self._bulk_task_tip = None
        self._bulk_task_type = None

    def _set_bulk_task_tip_content(self, content: str) -> None:
        if self._bulk_task_tip is None:
            return
        self._bulk_task_tip.content = content
        self._bulk_task_tip.contentLabel.setText(content)
        self._bulk_task_tip.adjustSize()

    def _clear_bulk_task_tip(self) -> None:
        if self._bulk_task_tip is None:
            return
        tip = self._bulk_task_tip
        self._bulk_task_tip = None
        self._bulk_task_type = None
        tip.close()

    def _show_status(self, level: str, message: str) -> None:
        level = level.lower().strip()
        if level == "error":
            InfoBar.error("Ошибка", message, position=InfoBarPosition.TOP_RIGHT, duration=6000, parent=self)
        elif level == "warning":
            InfoBar.warning("Внимание", message, position=InfoBarPosition.TOP_RIGHT, duration=3000, parent=self)
        elif level == "success":
            InfoBar.success("Успешно", message, position=InfoBarPosition.TOP_RIGHT, duration=2200, parent=self)
        else:
            InfoBar.info("Инфо", message, position=InfoBarPosition.TOP_RIGHT, duration=2200, parent=self)

    def _import_nodes_from_clipboard(self) -> None:
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip() if clipboard is not None else ""
        if not text:
            self._show_status("warning", "Буфер обмена пуст")
            return

        added, errors = self.controller.import_nodes_from_text(text)
        if added:
            self._show_status("success", f"Импортировано серверов: {added}")
        if errors:
            preview = "; ".join(errors[:2])
            self._show_status("warning", f"Некоторые ссылки не удалось импортировать: {preview}")
        if not added and not errors:
            self._show_status("warning", "Новых серверов не импортировано")

    def _ping_requested(self, ids: set[str]) -> None:
        self.nodes_page.start_ping_activity(ids or None)
        if ids:
            self.controller.ping_nodes(ids)
        else:
            self.controller.ping_nodes(None)

    def _speed_test_requested(self, ids: set[str]) -> None:
        started = self.controller.speed_test_nodes(ids or None)
        if started:
            self._speed_test_was_cancelled = False
            self.nodes_page.start_speed_activity()

    def _cancel_speed_test_requested(self) -> None:
        if self.controller.cancel_speed_test():
            self.nodes_page.mark_speed_test_stopping()
            if self._bulk_task_tip and self._bulk_task_type == "speed":
                self._set_bulk_task_tip_content("Останавливаю...")

    def _on_speed_test_cancelled(self, _completed: int, _total: int) -> None:
        self._speed_test_was_cancelled = True

    def _on_speed_progress_updated(self, node_id: str, percent: int) -> None:
        self.nodes_page.update_speed_progress(node_id, percent)

    def _on_speed_updated(self, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
        self.nodes_page.update_speed(node_id, speed_mbps)
        self.nodes_page.update_alive_status(node_id, is_alive)
        self.nodes_page.refresh_detail()

    def _on_edit_node(self, node_id: str) -> None:
        node = self.controller._get_node_by_id(node_id)
        if not node:
            return
        groups = self.controller.get_all_groups()
        dialog = NodeEditDialog(node, groups, self)
        if dialog.exec() == int(QDialog.DialogCode.Accepted):
            self.controller.update_node(node_id, dialog.get_updated_fields())

    def _on_bulk_edit_nodes(self, node_ids: set[str]) -> None:
        if not node_ids:
            return
        groups = self.controller.get_all_groups()
        dialog = BulkEditDialog(len(node_ids), groups, self)
        if dialog.exec() == int(QDialog.DialogCode.Accepted):
            ops = dialog.get_operations()
            if ops["group"] or ops["add_tags"] or ops["remove_tags"]:
                count = self.controller.bulk_update_nodes(node_ids, ops)
                self._show_status("success", f"Обновлено серверов: {count}")

    def _export_outbound_json(self, node_id: str) -> None:
        payload = self.controller.export_node_outbound_json(node_id)
        if not payload:
            self._show_status("warning", "Выберите сервер для экспорта")
            return
        self._save_json_payload(payload, "outbound.json")

    def _export_runtime_json(self, node_id: str) -> None:
        payload = self.controller.export_runtime_config_json(node_id)
        if not payload:
            self._show_status("warning", "Выберите сервер для экспорта")
            return
        suggested_name = "singbox_config.json" if self.controller.is_singbox_editor_mode() else "xray_config.json"
        self._save_json_payload(payload, suggested_name)

    def _save_json_payload(self, payload: str, suggested_name: str) -> None:
        file_path, _ = QFileDialog.getSaveFileName(self, "Экспорт JSON", suggested_name, "JSON files (*.json)")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(payload)
            self._show_status("success", f"JSON экспортирован: {file_path}")
            return

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self._show_status("info", "Экспорт отменён, JSON скопирован в буфер обмена")

    @staticmethod
    def _core_title(core: str) -> str:
        return "sing-box" if core == "singbox" else "xray"

    def _load_config_editor_documents(self) -> None:
        for core in ("singbox", "xray"):
            self._load_core_config_document(core)

    def _load_core_config_document(self, core: str) -> None:
        try:
            if core == "singbox":
                path, text = self.controller.load_active_singbox_config_text()
            else:
                path, text = self.controller.load_active_xray_config_text()
        except Exception as exc:
            self.configs_page.set_status(core, "error", str(exc))
            return
        self.configs_page.set_document(core, path, text)
        template_path = (
            self.controller.get_active_singbox_template_path()
            if core == "singbox"
            else self.controller.get_active_xray_template_path()
        )
        self.configs_page.set_template_source(core, template_path)
        self.configs_page.set_status(core, "info", f"Открыта активная копия: {path.name}")

    def _open_core_config(self, core: str) -> None:
        title = self._core_title(core)
        base_dir = str(
            self.controller.get_singbox_template_dir()
            if core == "singbox"
            else self.controller.get_xray_template_dir()
        )
        file_path, _ = QFileDialog.getOpenFileName(self, f"Импортировать {title} template", base_dir, "JSON files (*.json)")
        if not file_path:
            return
        try:
            if core == "singbox":
                path, text = self.controller.import_singbox_template(file_path)
                template_path = self.controller.get_active_singbox_template_path()
            else:
                path, text = self.controller.import_xray_template(file_path)
                template_path = self.controller.get_active_xray_template_path()
        except Exception as exc:
            self.configs_page.set_status(core, "error", str(exc))
            self._show_status("error", str(exc).splitlines()[0])
            return
        self.configs_page.set_document(core, path, text)
        self.configs_page.set_template_source(core, template_path)
        self.configs_page.set_status(core, "info", f"Импортирован template. Активная копия: {path.name}")
        self._show_status("success", f"Импортирован template: {Path(file_path).name}")

    def _reset_core_config_to_template(self, core: str) -> None:
        if core == "singbox":
            ok, path, message = self.controller.reset_active_singbox_config_to_template()
            template_path = self.controller.get_active_singbox_template_path()
            loader = self.controller.load_active_singbox_config_text
        else:
            ok, path, message = self.controller.reset_active_xray_config_to_template()
            template_path = self.controller.get_active_xray_template_path()
            loader = self.controller.load_active_xray_config_text
        if not ok or path is None:
            self.configs_page.set_status(core, "error", message)
            self._show_status("error", message.splitlines()[0])
            return
        loaded_path, text = loader()
        self.configs_page.set_document(core, loaded_path, text)
        self.configs_page.set_template_source(core, template_path)
        self.configs_page.set_status(core, "success", message)
        self._show_status("success", message)

    def _save_core_config(self, core: str, text: str) -> None:
        try:
            if core == "singbox":
                path = self.controller.save_singbox_config_text(text)
            else:
                path = self.controller.save_xray_config_text(text)
        except Exception as exc:
            self.configs_page.set_status(core, "error", str(exc))
            self._show_status("error", str(exc).splitlines()[0])
            return
        self.configs_page.mark_saved(core, path, text)
        self.configs_page.set_status(core, "success", f"Сохранено: {path.name}")
        self._show_status("success", f"Сохранено: {path.name}")

    def _validate_core_config(self, core: str, text: str) -> None:
        if core == "singbox":
            ok, message = self.controller.validate_singbox_json_text(text)
        else:
            ok, message = self.controller.validate_xray_json_text(text)
        self.configs_page.set_status(core, "success" if ok else "error", message)
        if ok:
            self._show_status("success", "JSON корректен")

    def _apply_core_config(self, core: str, text: str) -> None:
        if core == "singbox":
            ok, path, message = self.controller.apply_singbox_config_text(text)
        else:
            ok, path, message = self.controller.apply_xray_config_text(text)
        if not ok:
            self.configs_page.set_status(core, "error", message)
            self._show_status("error", message.splitlines()[0])
            return
        if path is not None:
            self.configs_page.mark_saved(core, path, text)
        level = "info" if "Применяю" in message else "success"
        self.configs_page.set_status(core, level, message)
        self._show_status(level, message.splitlines()[0])

    def _on_dashboard_tun_toggled(self, checked: bool) -> None:
        from copy import deepcopy
        settings = deepcopy(self.controller.state.settings)
        settings.tun_mode = checked
        if checked:
            settings.enable_system_proxy = False
        self.controller.update_settings(settings)

    def _on_dashboard_proxy_toggled(self, checked: bool) -> None:
        from copy import deepcopy
        settings = deepcopy(self.controller.state.settings)
        settings.enable_system_proxy = checked
        self.controller.update_settings(settings)

    def _set_mode_only(self, mode: str) -> None:
        from copy import deepcopy
        routing = deepcopy(self.controller.state.routing)
        routing.mode = mode
        self.controller.update_routing(routing)

    def _set_mode_from_tray(self, mode: str) -> None:
        self._set_mode_only(mode)

    def _set_password(self, password: str) -> None:
        self.controller.set_master_password(password)
        self._show_status("success", "Мастер-пароль включён")

    def _update_auto_lock_minutes(self, minutes: int) -> None:
        self.controller.state.security.auto_lock_minutes = max(1, minutes)
        self.controller.save()

    def _clear_logs_view(self) -> None:
        self.logs_page.clear_view()

    def _export_diagnostics(self) -> None:
        path = self.controller.build_diagnostics()
        self._show_status("success", f"Диагностика экспортирована: {path}")

    # ── Zapret ───────────────────────────────────────────────

    def _init_zapret_page(self) -> None:
        from ..zapret_manager import ZapretManager
        infos = ZapretManager.list_preset_infos()
        saved = self.controller.state.settings.zapret_preset
        self.zapret_page.set_presets(infos, saved)
        self.zapret_page.set_autostart(self.controller.state.settings.zapret_autostart)
        self._schedule_zapret_autostart()

    def _schedule_zapret_autostart(self, delay_ms: int = 0) -> None:
        if self._zapret_autostart_done or self._zapret_autostart_scheduled:
            return
        self._zapret_autostart_scheduled = True
        QTimer.singleShot(delay_ms, self._try_autostart_zapret)

    def _try_autostart_zapret(self) -> None:
        from ..zapret_manager import ZapretManager

        self._zapret_autostart_scheduled = False
        if self._zapret_autostart_done:
            return

        settings = self.controller.state.settings
        saved = settings.zapret_preset.strip()

        if not settings.zapret_autostart or not saved:
            self._zapret_autostart_done = True
            return

        if self.controller.zapret.running:
            self._zapret_autostart_done = True
            return

        infos = list(self.zapret_page._presets) or ZapretManager.list_preset_infos()
        if not infos:
            self._schedule_zapret_autostart(300)
            return

        self.zapret_page.set_presets(infos, saved)
        preset = next((info for info in infos if info.name == saved), None)
        if preset is None:
            self._zapret_autostart_done = True
            return

        self._zapret_autostart_done = True
        self._on_zapret_start(preset.name)

    def _on_zapret_start(self, preset_name: str) -> None:
        self.controller.state.settings.zapret_preset = preset_name
        self.controller.save()
        self.controller.zapret.start(preset_name)

    def _on_zapret_stop(self) -> None:
        self.controller.zapret.stop()

    def _on_zapret_autostart_changed(self, enabled: bool) -> None:
        self.controller.state.settings.zapret_autostart = enabled
        self.controller.save()

    def _on_zapret_started(self) -> None:
        active = self.controller.state.settings.zapret_preset
        self.zapret_page.set_running(True, active)

    def _on_zapret_stopped(self) -> None:
        self.zapret_page.set_running(False)

    def _on_zapret_error(self, message: str) -> None:
        self.zapret_page.set_error(message)
        self._show_status("error", f"Zapret: {message}")

    def _check_updates(self, silent: bool = False) -> None:
        if getattr(self, "_update_in_progress", False):
            return
        self._update_in_progress = True
        self._pending_update: AppUpdate | None = None
        self._update_checker = UpdateChecker(parent=self)
        self._update_checker.result.connect(lambda u: self._on_update_check_result(u, silent))
        self._update_checker.error.connect(lambda e: self._on_update_check_error(e, silent))
        self._update_checker.start()
        if not silent:
            self.updates_page.show_checking()

    def _on_update_check_error(self, err: str, silent: bool) -> None:
        self._update_in_progress = False
        if not silent:
            self.updates_page.show_idle()
            self.updates_page.set_app_error(f"Ошибка проверки: {err}")
            self._show_status("error", f"Ошибка проверки обновлений: {err}")

    def _on_update_check_result(self, update: AppUpdate | None, silent: bool) -> None:
        self._update_in_progress = False
        if update is None:
            self.updates_page.show_up_to_date()
            if not silent:
                self._show_status("info", "У вас установлена последняя версия")
            return

        if not self.controller.state.settings.allow_updates:
            self._pending_update = None
            self.updates_page.show_idle()
            self.updates_page.set_app_status(
                f"Доступна новая версия: v{update.version}. Установка отключена в настройках"
            )
            if not silent:
                self._show_status("warning", "Доступно обновление, но установка отключена в настройках")
            return

        self._pending_update = update
        self.updates_page.show_update_available(update.version)
        try:
            self.updates_page.download_btn.clicked.disconnect()
        except TypeError:
            pass
        self.updates_page.download_btn.clicked.connect(
            lambda: self._start_update_download(self._pending_update)
        )

        if silent:
            return

        # Switch to Updates page and show dialog
        self.switchTo(self.updates_page)

        from qfluentwidgets import MessageBox
        box = MessageBox(
            "Доступно обновление",
            f"Доступна новая версия v{update.version}.\n"
            f"Текущая: v{APP_VERSION}\n\n"
            f"Приложение скачает обновление, закроется и перезапустится автоматически.",
            self,
        )
        box.yesButton.setText("Скачать и установить")
        box.cancelButton.setText("Позже")
        if box.exec():
            self._start_update_download(update)

    def _start_update_download(self, update: AppUpdate) -> None:
        if not self.controller.state.settings.allow_updates:
            self.updates_page.show_idle()
            self.updates_page.set_app_status("Установка обновлений отключена в настройках")
            self._show_status("warning", "Установка обновлений отключена в настройках")
            return

        self._update_in_progress = True
        self.switchTo(self.updates_page)
        self.updates_page.show_download_progress(0)

        # Use proxy if connected
        proxy_url = None
        if self.controller.connected:
            from ..constants import PROXY_HOST
            port = self.controller.get_effective_http_proxy_port()
            if port:
                proxy_url = f"http://{PROXY_HOST}:{port}"

        restart_in_tray = self._tray_available and not self.isVisible()

        self._update_downloader = UpdateDownloader(
            update,
            proxy_url=proxy_url,
            restart_in_tray=restart_in_tray,
            parent=self,
        )
        self._update_downloader.progress.connect(self.updates_page.show_download_progress)
        self._update_downloader.status.connect(self.updates_page.set_app_status)
        self._update_downloader.finished_ok.connect(self._on_update_ready)
        self._update_downloader.error.connect(self._on_update_error)
        self._update_downloader.start()

    def _on_update_ready(self) -> None:
        self.updates_page.set_app_status("Обновление загружено. Перезапуск...")
        self._show_status("success", "Обновление загружено. Перезапуск...")
        QTimer.singleShot(1500, self._quit_for_update)

    def _on_update_error(self, err: str) -> None:
        self._update_in_progress = False
        self.updates_page.show_idle()
        self.updates_page.set_app_error(f"Ошибка: {err}")
        self._show_status("error", err)

    def _quit_for_update(self) -> None:
        self._quitting = True
        self._save_geometry()
        self.controller.shutdown()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def _consume_update_error_log(self) -> None:
        error_log = LOG_DIR / "update_error.log"
        if not error_log.exists():
            return
        archived_log = LOG_DIR / "update_error.last.log"
        try:
            content = error_log.read_text(encoding="utf-8").strip()
        except Exception:
            content = ""
        try:
            if archived_log.exists():
                archived_log.unlink()
            error_log.replace(archived_log)
        except Exception:
            pass

        message = "Предыдущее обновление не завершилось. См. data/logs/update_error.last.log"
        if content:
            self.logs_page.append_line("[update] previous install failed")
            for line in content.splitlines()[:10]:
                if line.strip():
                    self.logs_page.append_line(f"[update] {line.strip()}")
        self.updates_page.set_app_error(message)
        QTimer.singleShot(0, lambda: self._show_status("error", message))

    def _check_xray_updates(self) -> None:
        self.updates_page.set_xray_status("Проверка обновлений Xray...")
        self.controller.run_xray_core_update(False, silent=False)

    def _update_xray_core(self) -> None:
        self.updates_page.set_xray_status("Обновление Xray...")
        self.controller.run_xray_core_update(True, silent=False)

    def _apply_theme(self, theme_name: str, accent_color: str) -> None:
        normalized = theme_name.lower().strip()
        if normalized == "dark":
            setTheme(Theme.DARK)
        elif normalized == "light":
            setTheme(Theme.LIGHT)
        else:
            setTheme(Theme.AUTO)

        value = accent_color.strip()
        if value:
            try:
                setThemeColor(value)
            except Exception:
                pass

    def _refresh_tray_tooltip(self) -> None:
        if self.tray is None:
            return
        node = self.controller.selected_node
        status = "Подключено" if self.controller.connected else "Отключено"
        if node is not None:
            node_text = node.name
        elif self.controller.is_singbox_editor_mode():
            node_text = self.controller.get_active_singbox_config_name()
        elif self.controller.uses_xray_raw_config():
            node_text = self.controller.get_active_xray_config_name()
        else:
            node_text = "Нет сервера"
        self.tray.setToolTip(f"{APP_NAME}\n{status}\n{node_text}")

    def _ensure_unlocked(self, startup: bool) -> bool:
        if not self.controller.state.security.enabled:
            return True

        while True:
            dialog = PasswordDialog("Разблокировка", self)
            result = dialog.exec()
            if result != int(QDialog.DialogCode.Accepted):
                if startup:
                    self._quit_app()
                return False

            if self.controller.unlock(dialog.password()):
                self._show_status("success", "Разблокировано")
                return True

            self._show_status("error", "Неверный пароль")

    def _load_with_passphrase(self) -> bool:
        if self.controller.load():
            self._geometry_persistence_ready = True
            return True

        # State file is encrypted — ask for passphrase
        while True:
            dialog = PasswordDialog("Зашифрованные данные", self)
            dialog.password_edit.setPlaceholderText("Введите пароль шифрования")
            result = dialog.exec()
            if result != int(QDialog.DialogCode.Accepted):
                self._quit_app()
                return False

            passphrase = dialog.password()
            if not passphrase:
                continue

            self.controller.storage.passphrase = passphrase
            try:
                self.controller.load()
                self._geometry_persistence_ready = True
                return True
            except Exception:
                self._show_status("error", "Неверный пароль шифрования")

    def _export_backup(self) -> None:
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт резервной копии", "xray_fluent_backup.json", "Backup files (*.json)"
        )
        if not file_path:
            return

        passphrase = ""
        dialog = PasswordDialog("Зашифровать резервную копию?", self)
        dialog.password_edit.setPlaceholderText("Пароль (оставьте пустым для открытого формата)")
        if dialog.exec() == int(QDialog.DialogCode.Accepted):
            passphrase = dialog.password()

        try:
            from pathlib import Path
            self.controller.export_backup(Path(file_path), passphrase)
            self._show_status("success", f"Резервная копия экспортирована: {file_path}")
        except Exception as exc:
            self._show_status("error", f"Ошибка экспорта: {exc}")

    def _import_backup(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Импорт резервной копии", "", "Backup files (*.json);;All files (*)"
        )
        if not file_path:
            return

        from pathlib import Path
        path = Path(file_path)
        raw = path.read_text(encoding="utf-8").strip()

        passphrase = ""
        from ..security import is_passphrase_encrypted
        if is_passphrase_encrypted(raw):
            dialog = PasswordDialog("Расшифровать резервную копию", self)
            dialog.password_edit.setPlaceholderText("Введите пароль резервной копии")
            if dialog.exec() != int(QDialog.DialogCode.Accepted):
                return
            passphrase = dialog.password()

        try:
            self.controller.import_backup(path, passphrase)
            self._load_config_editor_documents()
            self._show_status("success", "Резервная копия успешно импортирована")
        except PassphraseRequired:
            self._show_status("error", "Для этой резервной копии требуется пароль")
        except Exception as exc:
            self._show_status("error", f"Ошибка импорта: {exc}")

    def _set_encryption(self, passphrase: str) -> None:
        self.controller.set_data_passphrase(passphrase)
        self.settings_page.set_encryption_active(True)

    def _disable_encryption(self) -> None:
        self.controller.clear_data_passphrase()
        self.settings_page.set_encryption_active(False)

    def _toggle_window_visible(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.activateWindow()
            self.raise_()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in {QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick}:
            self._toggle_window_visible()

    def _quit_app(self) -> None:
        self._quitting = True
        self._save_geometry()
        self.controller.shutdown()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def _save_geometry(self) -> None:
        controller = getattr(self, "controller", None)
        if controller is None:
            return
        if self.isMinimized() or self.isMaximized():
            return
        geo = self.geometry()
        s = controller.state.settings
        s.window_x = geo.x()
        s.window_y = geo.y()
        s.window_width = geo.width()
        s.window_height = geo.height()
        if self._geometry_persistence_ready:
            controller.schedule_save()

    def moveEvent(self, e) -> None:
        super().moveEvent(e)
        self._save_geometry()

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        self._save_geometry()

    def closeEvent(self, e: QCloseEvent) -> None:
        if self._quitting:
            e.accept()
            return

        if not self._tray_available:
            self._quitting = True
            self._save_geometry()
            self.controller.shutdown()
            e.accept()
            app = QApplication.instance()
            if app is not None:
                app.quit()
            return

        self._save_geometry()
        self.controller.save()
        e.ignore()
        self.hide()
        if self.tray is not None and not self._tray_notified:
            self.tray.showMessage(APP_NAME, "Приложение свёрнуто в системный трей", QSystemTrayIcon.MessageIcon.Information, 2000)
            self._tray_notified = True
