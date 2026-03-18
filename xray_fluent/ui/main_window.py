from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QAction, QActionGroup, QCloseEvent, QGuiApplication, QIcon
from PyQt6.QtWidgets import QApplication, QDialog, QFileDialog, QMenu, QSystemTrayIcon
from qfluentwidgets import (
    FluentIcon as FIF,
    FluentWindow,
    InfoBar,
    InfoBarPosition,
    NavigationItemPosition,
    Theme,
    setTheme,
    setThemeColor,
)

from ..app_controller import AppController
from ..storage import PassphraseRequired
from ..constants import APP_NAME, APP_VERSION
from ..models import AppSettings, Node, RoutingSettings
from ..app_updater import AppUpdate, UpdateChecker, UpdateDownloader
from ..xray_core_updater import XrayCoreUpdateResult
from .bulk_edit_dialog import BulkEditDialog
from .dashboard_page import DashboardPage
from .lock_dialog import PasswordDialog
from .logs_page import LogsPage
from .node_edit_dialog import NodeEditDialog
from .nodes_page import NodesPage
from .routing_page import RoutingPage
from .settings_page import SettingsPage
from .updates_page import UpdatesPage


class MainWindow(FluentWindow):
    def __init__(self, force_minimized: bool = False, defer_init: bool = False):
        super().__init__()
        self.force_minimized = force_minimized
        self._quitting = False
        self._tray_notified = False
        self._initialized = False

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
        self.routing_page = RoutingPage(self)
        self.logs_page = LogsPage(self)
        self.settings_page = SettingsPage(self)
        self.updates_page = UpdatesPage(self)

        self._create_navigation()
        self._create_tray()
        self._connect_signals()
        self._init_window()

        loaded = self._load_with_passphrase()

        unlocked = True
        if loaded and self.controller.state.security.enabled:
            self.controller.locked = True
            unlocked = self._ensure_unlocked(startup=True)

        if loaded and unlocked:
            self.controller.auto_connect_if_needed()

        # Set Xray version on updates page
        from ..xray_manager import get_xray_version
        xv = get_xray_version(self.controller.state.settings.xray_path)
        self.updates_page.set_xray_version(xv or "")

        if self.controller.state.settings.check_updates:
            QTimer.singleShot(2500, lambda: self._check_updates(silent=True))

        if self.controller.state.settings.xray_auto_update:
            QTimer.singleShot(4500, lambda: self.controller.run_xray_core_update(True, silent=True))

    def _create_navigation(self) -> None:
        self.navigationInterface.setMinimumExpandWidth(700)
        self.navigationInterface.setExpandWidth(200)
        self.addSubInterface(self.dashboard_page, FIF.SPEED_HIGH, "Dashboard")
        self.addSubInterface(self.nodes_page, FIF.LINK, "Nodes")
        self.addSubInterface(self.routing_page, FIF.GLOBE, "Routing")
        self.addSubInterface(self.logs_page, FIF.DOCUMENT, "Logs")
        self.addSubInterface(self.updates_page, FIF.UPDATE, "Updates", NavigationItemPosition.BOTTOM)
        self.addSubInterface(self.settings_page, FIF.SETTING, "Settings", NavigationItemPosition.BOTTOM)

    def _create_tray(self) -> None:
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(QIcon(":/qfluentwidgets/images/logo.png"))
        self.tray.setToolTip(APP_NAME)

        menu = QMenu()
        self.tray_show_action = QAction("Show", self)
        self.tray_connect_action = QAction("Connect", self)
        self.tray_next_action = QAction("Next node", self)
        self.tray_quit_action = QAction("Quit", self)

        self.tray_mode_menu = QMenu("Mode", menu)
        self.tray_mode_group = QActionGroup(self)
        self.tray_mode_group.setExclusive(True)
        self.tray_mode_global = QAction("Global", self)
        self.tray_mode_global.setCheckable(True)
        self.tray_mode_rule = QAction("Rule", self)
        self.tray_mode_rule.setCheckable(True)
        self.tray_mode_direct = QAction("Direct", self)
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
        self.dashboard_page.test_requested.connect(self.controller.test_connectivity)
        self.dashboard_page.node_selected.connect(self.controller.set_selected_node)
        self.dashboard_page.next_requested.connect(self.controller.switch_next_node)
        self.dashboard_page.prev_requested.connect(self.controller.switch_prev_node)
        self.dashboard_page.mode_changed.connect(self._set_mode_only)
        self.dashboard_page.toggle_connection_requested.connect(self.controller.toggle_connection)
        self.dashboard_page.nodes_requested.connect(lambda: self.switchTo(self.nodes_page))
        self.dashboard_page.routing_requested.connect(lambda: self.switchTo(self.routing_page))
        self.dashboard_page.logs_requested.connect(lambda: self.switchTo(self.logs_page))
        self.dashboard_page.settings_requested.connect(lambda: self.switchTo(self.settings_page))

        self.nodes_page.import_clipboard_requested.connect(self._import_nodes_from_clipboard)
        self.nodes_page.delete_requested.connect(self.controller.remove_nodes)
        self.nodes_page.selected_node_changed.connect(self.controller.set_selected_node)
        self.nodes_page.ping_requested.connect(self._ping_requested)
        self.nodes_page.export_outbound_json_requested.connect(self._export_outbound_json)
        self.nodes_page.export_runtime_json_requested.connect(self._export_runtime_json)
        self.nodes_page.edit_node_requested.connect(self._on_edit_node)
        self.nodes_page.bulk_edit_requested.connect(self._on_bulk_edit_nodes)

        self.routing_page.apply_requested.connect(self.controller.update_routing)

        self.logs_page.clear_requested.connect(self._clear_logs_view)
        self.logs_page.export_diag_requested.connect(self._export_diagnostics)

        self.settings_page.save_requested.connect(self.controller.update_settings)
        self.settings_page.auto_lock_minutes_changed.connect(self._update_auto_lock_minutes)
        self.settings_page.set_password_requested.connect(self._set_password)
        self.settings_page.disable_password_requested.connect(self.controller.disable_master_password)
        self.settings_page.lock_now_requested.connect(self.controller.lock)
        self.updates_page.check_app_requested.connect(self._check_updates)
        self.updates_page.check_xray_requested.connect(lambda: self.controller.run_xray_core_update(False, silent=False))
        self.updates_page.update_xray_requested.connect(lambda: self.controller.run_xray_core_update(True, silent=False))
        self.settings_page.export_backup_requested.connect(self._export_backup)
        self.settings_page.import_backup_requested.connect(self._import_backup)
        self.settings_page.set_encryption_requested.connect(self._set_encryption)
        self.settings_page.disable_encryption_requested.connect(self._disable_encryption)

        self.controller.nodes_changed.connect(self._on_nodes_changed)
        self.controller.selection_changed.connect(self._on_selection_changed)
        self.controller.connection_changed.connect(self._on_connection_changed)
        self.controller.routing_changed.connect(self._on_routing_changed)
        self.controller.settings_changed.connect(self._on_settings_changed)
        self.controller.log_line.connect(self.logs_page.append_line)
        self.controller.status.connect(self._show_status)
        self.controller.ping_updated.connect(self._on_ping_updated)
        self.controller.connectivity_test_done.connect(self._on_connectivity_test_done)
        self.controller.live_metrics_updated.connect(self._on_live_metrics_updated)
        self.controller.xray_update_result.connect(self._on_xray_update_result)
        self.controller.lock_state_changed.connect(self._on_lock_state_changed)

    def _init_window(self) -> None:
        s = self.controller.state.settings
        self.resize(s.window_width, s.window_height)
        if s.window_x >= 0 and s.window_y >= 0:
            if self._is_position_on_screen(s.window_x, s.window_y):
                self.move(s.window_x, s.window_y)
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(":/qfluentwidgets/images/logo.png"))

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
        self.tray_connect_action.setText("Disconnect" if connected else "Connect")
        self._refresh_tray_tooltip()

    def _on_routing_changed(self, routing: RoutingSettings) -> None:
        self.routing_page.set_routing(routing)
        self.dashboard_page.set_routing_snapshot(routing)
        self.tray_mode_global.setChecked(routing.mode == "global")
        self.tray_mode_rule.setChecked(routing.mode == "rule")
        self.tray_mode_direct.setChecked(routing.mode == "direct")

    def _on_settings_changed(self, settings: AppSettings) -> None:
        self.settings_page.set_values(settings, self.controller.state.security)
        self.settings_page.set_encryption_active(self.controller.is_data_encrypted())
        self.dashboard_page.set_settings_snapshot(settings)
        self._apply_theme(settings.theme, settings.accent_color)

    def _on_ping_updated(self, node_id: str, ping_ms: int | None) -> None:
        self.nodes_page.update_ping(node_id, ping_ms)
        node = self.controller.selected_node
        if node and node.id == node_id:
            self.dashboard_page.set_selected_latency(ping_ms)

    def _on_live_metrics_updated(self, payload: dict[str, object]) -> None:
        down_bps = float(payload.get("down_bps") or 0.0)
        up_bps = float(payload.get("up_bps") or 0.0)
        latency = payload.get("latency_ms")
        latency_ms = int(latency) if isinstance(latency, int) else None
        self.dashboard_page.set_live_metrics(down_bps, up_bps, latency_ms)

    def _on_xray_update_result(self, result: XrayCoreUpdateResult) -> None:
        self.logs_page.append_line(f"[core-update] {result.status}: {result.message}")

    def _on_connectivity_test_done(self, ok: bool, message: str, elapsed_ms: int | None) -> None:
        if ok and elapsed_ms is not None:
            self.logs_page.append_line(f"[test] ok {elapsed_ms} ms | {message}")
        else:
            self.logs_page.append_line(f"[test] fail | {message}")

    def _on_lock_state_changed(self, locked: bool) -> None:
        if locked:
            self._show_status("warning", "App locked")
            self._ensure_unlocked(startup=False)

    def _show_status(self, level: str, message: str) -> None:
        level = level.lower().strip()
        if level == "error":
            InfoBar.error("Error", message, position=InfoBarPosition.TOP_RIGHT, duration=3000, parent=self)
        elif level == "warning":
            InfoBar.warning("Warning", message, position=InfoBarPosition.TOP_RIGHT, duration=3000, parent=self)
        elif level == "success":
            InfoBar.success("Success", message, position=InfoBarPosition.TOP_RIGHT, duration=2200, parent=self)
        else:
            InfoBar.info("Info", message, position=InfoBarPosition.TOP_RIGHT, duration=2200, parent=self)

    def _import_nodes_from_clipboard(self) -> None:
        clipboard = QApplication.clipboard()
        text = clipboard.text().strip() if clipboard is not None else ""
        if not text:
            self._show_status("warning", "Clipboard is empty")
            return

        added, errors = self.controller.import_nodes_from_text(text)
        if added:
            self._show_status("success", f"Imported {added} node(s)")
        if errors:
            preview = "; ".join(errors[:2])
            self._show_status("warning", f"Some links failed: {preview}")
        if not added and not errors:
            self._show_status("warning", "No new nodes imported")

    def _ping_requested(self, ids: set[str]) -> None:
        if ids:
            self.controller.ping_nodes(ids)
        else:
            self.controller.ping_nodes(None)

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
                self._show_status("success", f"Updated {count} node(s)")

    def _export_outbound_json(self, node_id: str) -> None:
        payload = self.controller.export_node_outbound_json(node_id)
        if not payload:
            self._show_status("warning", "Select one node to export")
            return
        self._save_json_payload(payload, "outbound.json")

    def _export_runtime_json(self, node_id: str) -> None:
        payload = self.controller.export_runtime_config_json(node_id)
        if not payload:
            self._show_status("warning", "Select one node to export")
            return
        self._save_json_payload(payload, "xray_config.json")

    def _save_json_payload(self, payload: str, suggested_name: str) -> None:
        file_path, _ = QFileDialog.getSaveFileName(self, "Export JSON", suggested_name, "JSON files (*.json)")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(payload)
            self._show_status("success", f"Exported JSON: {file_path}")
            return

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(payload)
            self._show_status("info", "Export cancelled, JSON copied to clipboard")

    def _set_mode_only(self, mode: str) -> None:
        routing = self.controller.state.routing
        self.controller.update_routing(
            mode,
            routing.direct_domains,
            routing.proxy_domains,
            routing.block_domains,
            routing.bypass_lan,
            routing.dns_mode,
        )

    def _set_mode_from_tray(self, mode: str) -> None:
        self._set_mode_only(mode)

    def _set_password(self, password: str) -> None:
        self.controller.set_master_password(password)
        self._show_status("success", "Master password enabled")

    def _update_auto_lock_minutes(self, minutes: int) -> None:
        self.controller.state.security.auto_lock_minutes = max(1, minutes)
        self.controller.save()

    def _clear_logs_view(self) -> None:
        self.logs_page.clear_view()

    def _export_diagnostics(self) -> None:
        path = self.controller.build_diagnostics()
        self._show_status("success", f"Diagnostics exported: {path}")

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
            self.updates_page.set_app_status(f"Check failed: {err}")
            self._show_status("error", f"Update check failed: {err}")

    def _on_update_check_result(self, update: AppUpdate | None, silent: bool) -> None:
        self._update_in_progress = False
        if update is None:
            self.updates_page.show_up_to_date()
            if not silent:
                self._show_status("info", "You are on the latest version")
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

        # Switch to Updates page and show dialog
        self.switchTo(self.updates_page)

        from qfluentwidgets import MessageBox
        box = MessageBox(
            "Update available",
            f"New version v{update.version} is available.\n"
            f"Current: v{APP_VERSION}\n\n"
            f"The app will download, close, and restart automatically.",
            self,
        )
        box.yesButton.setText("Download && Install")
        box.cancelButton.setText("Later")
        if box.exec():
            self._start_update_download(update)

    def _start_update_download(self, update: AppUpdate) -> None:
        self._update_in_progress = True
        self.switchTo(self.updates_page)
        self.updates_page.show_download_progress(0)

        # Use proxy if connected
        proxy_url = None
        if self.controller.connected:
            from ..constants import PROXY_HOST, DEFAULT_HTTP_PORT
            port = self.controller.state.settings.http_port or DEFAULT_HTTP_PORT
            proxy_url = f"http://{PROXY_HOST}:{port}"

        self._update_downloader = UpdateDownloader(update, proxy_url=proxy_url, parent=self)
        self._update_downloader.progress.connect(self.updates_page.show_download_progress)
        self._update_downloader.finished_ok.connect(self._on_update_ready)
        self._update_downloader.error.connect(self._on_update_error)
        self._update_downloader.start()

    def _on_update_ready(self) -> None:
        self.updates_page.set_app_status("Update downloaded. Restarting...")
        self._show_status("success", "Update downloaded. Restarting...")
        QTimer.singleShot(1500, lambda: QApplication.quit())

    def _on_update_error(self, err: str) -> None:
        self.updates_page.show_idle()
        self.updates_page.set_app_status(f"Update failed: {err}")
        self._show_status("error", f"Update failed: {err}")

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
        node = self.controller.selected_node
        status = "Connected" if self.controller.connected else "Disconnected"
        node_text = node.name if node else "No node"
        self.tray.setToolTip(f"{APP_NAME}\n{status}\n{node_text}")

    def _ensure_unlocked(self, startup: bool) -> bool:
        if not self.controller.state.security.enabled:
            return True

        while True:
            dialog = PasswordDialog("Unlock zapret kvn", self)
            result = dialog.exec()
            if result != int(QDialog.DialogCode.Accepted):
                if startup:
                    self._quit_app()
                return False

            if self.controller.unlock(dialog.password()):
                self._show_status("success", "Unlocked")
                return True

            self._show_status("error", "Wrong password")

    def _load_with_passphrase(self) -> bool:
        if self.controller.load():
            return True

        # State file is encrypted — ask for passphrase
        while True:
            dialog = PasswordDialog("Encrypted data", self)
            dialog.password_edit.setPlaceholderText("Enter encryption passphrase")
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
                return True
            except Exception:
                self._show_status("error", "Wrong passphrase")

    def _export_backup(self) -> None:
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export backup", "xray_fluent_backup.json", "Backup files (*.json)"
        )
        if not file_path:
            return

        passphrase = ""
        dialog = PasswordDialog("Encrypt backup?", self)
        dialog.password_edit.setPlaceholderText("Passphrase (leave empty for plain)")
        if dialog.exec() == int(QDialog.DialogCode.Accepted):
            passphrase = dialog.password()

        try:
            from pathlib import Path
            self.controller.export_backup(Path(file_path), passphrase)
            self._show_status("success", f"Backup exported: {file_path}")
        except Exception as exc:
            self._show_status("error", f"Export failed: {exc}")

    def _import_backup(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import backup", "", "Backup files (*.json);;All files (*)"
        )
        if not file_path:
            return

        from pathlib import Path
        path = Path(file_path)
        raw = path.read_text(encoding="utf-8").strip()

        passphrase = ""
        from ..security import is_passphrase_encrypted
        if is_passphrase_encrypted(raw):
            dialog = PasswordDialog("Decrypt backup", self)
            dialog.password_edit.setPlaceholderText("Enter backup passphrase")
            if dialog.exec() != int(QDialog.DialogCode.Accepted):
                return
            passphrase = dialog.password()

        try:
            self.controller.import_backup(path, passphrase)
            self._show_status("success", "Backup imported successfully")
        except PassphraseRequired:
            self._show_status("error", "Passphrase required for this backup")
        except Exception as exc:
            self._show_status("error", f"Import failed: {exc}")

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

        self._save_geometry()
        self.controller.save()
        e.ignore()
        self.hide()
        if not self._tray_notified:
            self.tray.showMessage(APP_NAME, "App is running in system tray", QSystemTrayIcon.MessageIcon.Information, 2000)
            self._tray_notified = True
