from __future__ import annotations

from copy import deepcopy

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QFileDialog, QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    LineEdit,
    PasswordLineEdit,
    PrimaryPushSettingCard,
    PushButton,
    PushSettingCard,
    SettingCard,
    SpinBox,
    SettingCardGroup,
    SmoothScrollArea,
    SubtitleLabel,
    SwitchSettingCard,
)
from qfluentwidgets.components.settings.setting_card import ColorPickerButton

from ..constants import SINGBOX_PATH_DEFAULT, XRAY_PATH_DEFAULT
from ..models import AppSettings, SecuritySettings
from ..path_utils import normalize_configured_path, resolve_configured_path


class _ComboCard(SettingCard):
    """Setting card with a combo box on the right."""

    def __init__(self, icon, title, content, items: list[tuple[str, str]], parent=None):
        super().__init__(icon, title, content, parent)
        self.combo = ComboBox(self)
        self.combo.setMinimumWidth(220)
        for text, data in items:
            self.combo.addItem(text, userData=data)
        self.hBoxLayout.addWidget(self.combo, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _SpinCard(SettingCard):
    """Setting card with a spin box on the right."""

    def __init__(self, icon, title, content, min_val=1, max_val=65535, parent=None):
        super().__init__(icon, title, content, parent)
        self.spin = SpinBox(self)
        self.spin.setRange(min_val, max_val)
        self.spin.setMinimumWidth(180)
        self.hBoxLayout.addWidget(self.spin, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _ColorCard(SettingCard):
    """Setting card with a color picker button on the right."""

    def __init__(self, icon, title, content, parent=None):
        super().__init__(icon, title, content, parent)
        self.picker = ColorPickerButton(QColor("#0078D4"), title, self)
        self.hBoxLayout.addWidget(self.picker, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _LineEditCard(SettingCard):
    """Setting card with a line edit on the right."""

    def __init__(self, icon, title, content, placeholder="", parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setMinimumWidth(420)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _BrowseCard(SettingCard):
    """Setting card with a line edit + browse button on the right."""

    def __init__(self, icon, title, content, parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = LineEdit(self)
        self.edit.setMinimumWidth(380)
        self.btn = PushButton("Browse", self)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(8)
        self.hBoxLayout.addWidget(self.btn, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)


class _PasswordActionCard(SettingCard):
    """Setting card with a password edit and action buttons."""

    def __init__(self, icon, title, content, placeholder="", buttons: list[str] | None = None, parent=None):
        super().__init__(icon, title, content, parent)
        self.edit = PasswordLineEdit(self)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setMinimumWidth(260)
        self.hBoxLayout.addWidget(self.edit, 0, Qt.AlignmentFlag.AlignRight)
        self.buttons: list[PushButton] = []
        for text in (buttons or []):
            self.hBoxLayout.addSpacing(8)
            btn = PushButton(text, self)
            self.hBoxLayout.addWidget(btn, 0, Qt.AlignmentFlag.AlignRight)
            self.buttons.append(btn)
        self.hBoxLayout.addSpacing(16)


class SettingsPage(QWidget):
    save_requested = pyqtSignal(object)
    auto_lock_minutes_changed = pyqtSignal(int)
    set_password_requested = pyqtSignal(str)
    disable_password_requested = pyqtSignal()
    lock_now_requested = pyqtSignal()
    # Update buttons moved to UpdatesPage
    export_backup_requested = pyqtSignal()
    import_backup_requested = pyqtSignal()
    set_encryption_requested = pyqtSignal(str)
    disable_encryption_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("settings")
        self._settings = AppSettings()
        self._security = SecuritySettings()
        self._loading = False

        # --- Outer layout with scroll area ---
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = SmoothScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(self._scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        self._scroll.setWidget(container)

        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(4)

        root.addWidget(SubtitleLabel("Settings", container))
        root.addSpacing(8)

        # ============================================================
        # Appearance
        # ============================================================
        appearance_group = SettingCardGroup("Appearance", container)

        self.theme_card = _ComboCard(
            FIF.BRUSH, "Theme", "Choose light, dark or follow system",
            [("System", "system"), ("Light", "light"), ("Dark", "dark")],
            parent=appearance_group,
        )
        self.accent_card = _ColorCard(
            FIF.PALETTE, "Accent color", "Choose accent color for UI highlights",
            parent=appearance_group,
        )

        appearance_group.addSettingCard(self.theme_card)
        appearance_group.addSettingCard(self.accent_card)
        root.addWidget(appearance_group)

        # ============================================================
        # Network
        # ============================================================
        network_group = SettingCardGroup("Network", container)

        self.socks_card = _SpinCard(
            FIF.CONNECT, "SOCKS port", "Local SOCKS5 proxy port",
            parent=network_group,
        )
        self.http_card = _SpinCard(
            FIF.GLOBE, "HTTP port", "Local HTTP proxy port",
            parent=network_group,
        )
        self.proxy_card = SwitchSettingCard(
            FIF.GLOBE, "Enable system proxy",
            "Automatically configure Windows proxy settings when connected",
            parent=network_group,
        )
        self.tun_card = SwitchSettingCard(
            FIF.WIFI, "TUN mode (VPN)",
            "Route all system traffic via virtual adapter. Requires Administrator.",
            parent=network_group,
        )
        self.reconnect_card = SwitchSettingCard(
            FIF.SYNC, "Reconnect on network change",
            "Automatically reconnect when your network adapter changes",
            parent=network_group,
        )

        network_group.addSettingCard(self.socks_card)
        network_group.addSettingCard(self.http_card)
        network_group.addSettingCard(self.proxy_card)
        network_group.addSettingCard(self.tun_card)
        network_group.addSettingCard(self.reconnect_card)
        root.addWidget(network_group)

        # ============================================================
        # Core paths
        # ============================================================
        paths_group = SettingCardGroup("Core paths", container)

        self.xray_path_card = _BrowseCard(
            FIF.COMMAND_PROMPT, "Xray core path", "Relative paths are resolved from the app folder",
            parent=paths_group,
        )
        self.singbox_path_card = _BrowseCard(
            FIF.COMMAND_PROMPT, "Sing-box path", "Optional; relative paths are resolved from the app folder",
            parent=paths_group,
        )

        paths_group.addSettingCard(self.xray_path_card)
        paths_group.addSettingCard(self.singbox_path_card)
        root.addWidget(paths_group)

        # ============================================================
        # Startup
        # ============================================================
        startup_group = SettingCardGroup("Startup", container)

        self.start_min_card = SwitchSettingCard(
            FIF.MINIMIZE, "Start minimized",
            "Launch the app hidden in system tray",
            parent=startup_group,
        )
        self.launch_card = SwitchSettingCard(
            FIF.POWER_BUTTON, "Run on Windows startup",
            "Start the app automatically when you log in",
            parent=startup_group,
        )

        startup_group.addSettingCard(self.start_min_card)
        startup_group.addSettingCard(self.launch_card)
        root.addWidget(startup_group)

        # ============================================================
        # Updates
        # ============================================================
        updates_group = SettingCardGroup("Updates", container)

        self.check_updates_card = SwitchSettingCard(
            FIF.UPDATE, "Check app updates",
            "Periodically check for new app versions on startup",
            parent=updates_group,
        )
        self.allow_updates_card = SwitchSettingCard(
            FIF.DOWNLOAD, "Allow updates",
            "Enable downloading and installing app updates",
            parent=updates_group,
        )
        self.xray_auto_update_card = SwitchSettingCard(
            FIF.CLOUD_DOWNLOAD, "Auto update Xray core",
            "Automatically update Xray core binary on startup",
            parent=updates_group,
        )

        updates_group.addSettingCard(self.check_updates_card)
        updates_group.addSettingCard(self.allow_updates_card)
        updates_group.addSettingCard(self.xray_auto_update_card)
        root.addWidget(updates_group)

        # ============================================================
        # Data
        # ============================================================
        data_group = SettingCardGroup("Data", container)

        self.encryption_card = _PasswordActionCard(
            FIF.FINGERPRINT, "Encryption passphrase",
            "Protect state file with a passphrase",
            placeholder="Enter passphrase",
            buttons=["Set encryption", "Disable encryption"],
            parent=data_group,
        )
        self.export_backup_card = PushSettingCard(
            "Export", FIF.SAVE, "Export backup",
            "Export full application state to a file",
            parent=data_group,
        )
        self.import_backup_card = PushSettingCard(
            "Import", FIF.FOLDER, "Import backup",
            "Restore application state from a backup file",
            parent=data_group,
        )

        data_group.addSettingCard(self.encryption_card)
        data_group.addSettingCard(self.export_backup_card)
        data_group.addSettingCard(self.import_backup_card)
        root.addWidget(data_group)

        # ============================================================
        # Security
        # ============================================================
        security_group = SettingCardGroup("Security", container)

        self.password_card = _PasswordActionCard(
            FIF.CERTIFICATE, "Master password",
            "Set a password to lock the app",
            placeholder="Set new password",
            buttons=["Set password", "Disable password", "Lock now"],
            parent=security_group,
        )
        self.auto_lock_card = _SpinCard(
            FIF.STOP_WATCH, "Auto lock (minutes)",
            "Lock the app after a period of inactivity",
            min_val=1, max_val=120, parent=security_group,
        )

        security_group.addSettingCard(self.password_card)
        security_group.addSettingCard(self.auto_lock_card)
        root.addWidget(security_group)

        root.addStretch(1)

        # ============================================================
        # Signal connections
        # ============================================================

        # Browse buttons
        self.xray_path_card.btn.clicked.connect(self._choose_xray_path)
        self.singbox_path_card.btn.clicked.connect(self._choose_singbox_path)

        # Password / encryption / backup buttons
        self.password_card.buttons[0].clicked.connect(self._emit_password)       # Set password
        self.password_card.buttons[1].clicked.connect(self.disable_password_requested)  # Disable password
        self.password_card.buttons[2].clicked.connect(self.lock_now_requested)    # Lock now

        self.encryption_card.buttons[0].clicked.connect(self._emit_set_encryption)  # Set encryption
        self.encryption_card.buttons[1].clicked.connect(self.disable_encryption_requested)  # Disable encryption

        self.export_backup_card.clicked.connect(self.export_backup_requested)
        self.import_backup_card.clicked.connect(self.import_backup_requested)

        # Update action buttons
        # Update buttons moved to UpdatesPage

        # --- Auto-save connections ---
        self.theme_card.combo.currentIndexChanged.connect(self._auto_save)
        self.accent_card.picker.colorChanged.connect(self._auto_save)
        self.socks_card.spin.valueChanged.connect(self._auto_save)
        self.http_card.spin.valueChanged.connect(self._auto_save)
        self.xray_path_card.edit.editingFinished.connect(self._auto_save)
        self.singbox_path_card.edit.editingFinished.connect(self._auto_save)

        self.tun_card.checkedChanged.connect(self._on_tun_toggled)
        self.start_min_card.checkedChanged.connect(self._auto_save)
        self.proxy_card.checkedChanged.connect(self._auto_save)
        self.launch_card.checkedChanged.connect(self._auto_save)
        self.reconnect_card.checkedChanged.connect(self._auto_save)
        self.check_updates_card.checkedChanged.connect(self._auto_save)
        self.allow_updates_card.checkedChanged.connect(self._auto_save)
        self.xray_auto_update_card.checkedChanged.connect(self._auto_save)

        self.auto_lock_card.spin.valueChanged.connect(self._auto_save)

    # ================================================================
    # Public API
    # ================================================================

    def set_values(self, settings: AppSettings, security: SecuritySettings) -> None:
        self._loading = True
        self._settings = deepcopy(settings)
        self._security = deepcopy(security)

        self._select_combo_data(self.theme_card.combo, settings.theme)
        self.accent_card.picker.setColor(QColor(settings.accent_color or "#0078D4"))
        self.socks_card.spin.setValue(settings.socks_port)
        self.http_card.spin.setValue(settings.http_port)
        self.xray_path_card.edit.setText(
            normalize_configured_path(
                settings.xray_path,
                default_path=XRAY_PATH_DEFAULT,
                use_default_if_empty=True,
                migrate_default_location=True,
            )
        )
        self.singbox_path_card.edit.setText(
            normalize_configured_path(
                settings.singbox_path,
                default_path=SINGBOX_PATH_DEFAULT,
                use_default_if_empty=True,
                migrate_default_location=True,
            )
        )
        self.tun_card.setChecked(settings.tun_mode)
        self.proxy_card.setEnabled(not settings.tun_mode)

        self.start_min_card.setChecked(settings.start_minimized)
        self.proxy_card.setChecked(settings.enable_system_proxy)
        self.launch_card.setChecked(settings.launch_on_startup)
        self.reconnect_card.setChecked(settings.reconnect_on_network_change)
        self.check_updates_card.setChecked(settings.check_updates)
        self.allow_updates_card.setChecked(settings.allow_updates)
        self.xray_auto_update_card.setChecked(settings.xray_auto_update)

        self.auto_lock_card.spin.setValue(security.auto_lock_minutes)
        self.password_card.edit.clear()
        self._loading = False

    def set_encryption_active(self, active: bool) -> None:
        self.encryption_card.buttons[1].setEnabled(active)  # Disable encryption btn

    # ================================================================
    # Private slots
    # ================================================================

    def _choose_xray_path(self) -> None:
        current_path = resolve_configured_path(
            self.xray_path_card.edit.text(),
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select xray.exe",
            str(current_path or XRAY_PATH_DEFAULT),
            "xray.exe (xray.exe)",
        )
        if file_path:
            self.xray_path_card.edit.setText(
                normalize_configured_path(
                    file_path,
                    default_path=XRAY_PATH_DEFAULT,
                    use_default_if_empty=True,
                    migrate_default_location=True,
                )
            )
            self._auto_save()

    def _choose_singbox_path(self) -> None:
        current_path = resolve_configured_path(
            self.singbox_path_card.edit.text(),
            default_path=SINGBOX_PATH_DEFAULT,
            migrate_default_location=True,
        )
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select sing-box.exe",
            str(current_path or SINGBOX_PATH_DEFAULT),
            "sing-box.exe (sing-box.exe)",
        )
        if file_path:
            self.singbox_path_card.edit.setText(
                normalize_configured_path(
                    file_path,
                    default_path=SINGBOX_PATH_DEFAULT,
                    migrate_default_location=True,
                )
            )
            self._auto_save()

    def _on_tun_toggled(self, checked: bool) -> None:
        self.proxy_card.setEnabled(not checked)
        self._auto_save()

    def _auto_save(self) -> None:
        if self._loading:
            return
        data = deepcopy(self._settings)
        data.theme = str(self.theme_card.combo.currentData() or "system")
        data.accent_color = self.accent_card.picker.color.name() or "#0078D4"
        data.socks_port = int(self.socks_card.spin.value())
        data.http_port = int(self.http_card.spin.value())
        data.xray_path = normalize_configured_path(
            self.xray_path_card.edit.text(),
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        data.singbox_path = normalize_configured_path(
            self.singbox_path_card.edit.text(),
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        self.xray_path_card.edit.setText(data.xray_path)
        self.singbox_path_card.edit.setText(data.singbox_path)
        data.tun_mode = self.tun_card.isChecked()
        data.start_minimized = self.start_min_card.isChecked()
        data.enable_system_proxy = self.proxy_card.isChecked()
        data.launch_on_startup = self.launch_card.isChecked()
        data.reconnect_on_network_change = self.reconnect_card.isChecked()
        data.check_updates = self.check_updates_card.isChecked()
        data.allow_updates = self.allow_updates_card.isChecked()
        data.xray_auto_update = self.xray_auto_update_card.isChecked()
        self.save_requested.emit(data)
        self.auto_lock_minutes_changed.emit(int(self.auto_lock_card.spin.value()))

    def _emit_set_encryption(self) -> None:
        value = self.encryption_card.edit.text().strip()
        if value:
            self.set_encryption_requested.emit(value)
            self.encryption_card.edit.clear()

    def _emit_password(self) -> None:
        value = self.password_card.edit.text().strip()
        if value:
            self.set_password_requested.emit(value)
            self.password_card.edit.clear()

    @staticmethod
    def _select_combo_data(combo: ComboBox, value: str) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return
