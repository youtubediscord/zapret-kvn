from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryPushButton,
    ProgressBar,
    PushButton,
    SubtitleLabel,
    TitleLabel,
)

from ..constants import APP_VERSION


class UpdatesPage(QWidget):
    check_app_requested = pyqtSignal()
    check_xray_requested = pyqtSignal()
    update_xray_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("updates")

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 28)
        root.setSpacing(20)

        title = SubtitleLabel("Updates", self)
        root.addWidget(title)

        # ── App version info ──
        app_box = QVBoxLayout()
        app_box.setSpacing(6)
        app_title = BodyLabel("zapret kvn", self)
        app_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        app_box.addWidget(app_title)

        self._app_version_label = BodyLabel(f"Current version: v{APP_VERSION}", self)
        app_box.addWidget(self._app_version_label)

        self._app_status = CaptionLabel("", self)
        self._app_status.setStyleSheet("color: #888;")
        app_box.addWidget(self._app_status)

        # Progress bar
        self._app_progress = ProgressBar(self)
        self._app_progress.setFixedHeight(4)
        self._app_progress.setValue(0)
        self._app_progress.hide()
        app_box.addWidget(self._app_progress)

        self._app_spinner = IndeterminateProgressBar(self)
        self._app_spinner.setFixedHeight(4)
        self._app_spinner.hide()
        app_box.addWidget(self._app_spinner)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.check_app_btn = PrimaryPushButton(FIF.SYNC, "Check for updates", self)
        self.download_btn = PushButton(FIF.DOWNLOAD, "Download & Install", self)
        self.download_btn.hide()
        btn_row.addWidget(self.check_app_btn)
        btn_row.addWidget(self.download_btn)
        btn_row.addStretch()
        app_box.addLayout(btn_row)

        root.addLayout(app_box)

        # Separator
        sep = QWidget(self)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: rgba(128,128,128,0.3);")
        root.addWidget(sep)

        # ── Xray core info ──
        xray_box = QVBoxLayout()
        xray_box.setSpacing(6)
        xray_title = BodyLabel("Xray Core", self)
        xray_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        xray_box.addWidget(xray_title)

        self._xray_version_label = BodyLabel("Version: loading...", self)
        xray_box.addWidget(self._xray_version_label)

        self._xray_status = CaptionLabel("", self)
        self._xray_status.setStyleSheet("color: #888;")
        xray_box.addWidget(self._xray_status)

        xray_btn_row = QHBoxLayout()
        xray_btn_row.setSpacing(10)
        self.check_xray_btn = PushButton(FIF.SYNC, "Check Xray updates", self)
        self.update_xray_btn = PrimaryPushButton(FIF.DOWNLOAD, "Update Xray core", self)
        xray_btn_row.addWidget(self.check_xray_btn)
        xray_btn_row.addWidget(self.update_xray_btn)
        xray_btn_row.addStretch()
        xray_box.addLayout(xray_btn_row)

        root.addLayout(xray_box)
        root.addStretch()

        # ── Connections ──
        self.check_app_btn.clicked.connect(self.check_app_requested)
        self.check_xray_btn.clicked.connect(self.check_xray_requested)
        self.update_xray_btn.clicked.connect(self.update_xray_requested)

    # ── Public API ──

    def set_xray_version(self, version: str) -> None:
        self._xray_version_label.setText(f"Version: {version}" if version else "Version: not found")

    def set_app_status(self, text: str) -> None:
        self._app_status.setText(text)

    def set_xray_status(self, text: str) -> None:
        self._xray_status.setText(text)

    def show_checking(self) -> None:
        self._app_progress.hide()
        self._app_spinner.show()
        self._app_spinner.start()
        self.check_app_btn.setEnabled(False)
        self._app_status.setText("Checking for updates...")

    def show_download_progress(self, percent: int) -> None:
        self._app_spinner.hide()
        self._app_progress.show()
        self._app_progress.setValue(percent)
        self._app_status.setText(f"Downloading: {percent}%")

    def show_idle(self) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self._app_progress.hide()
        self._app_progress.setValue(0)
        self.check_app_btn.setEnabled(True)
        self.download_btn.hide()

    def show_update_available(self, version: str) -> None:
        self._app_spinner.stop()
        self._app_spinner.hide()
        self.check_app_btn.setEnabled(True)
        self._app_status.setText(f"New version available: v{version}")
        self._app_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.download_btn.show()
        self.download_btn.setText(f"Download v{version} & Install")

    def show_up_to_date(self) -> None:
        self.show_idle()
        self._app_status.setText("You are on the latest version")
        self._app_status.setStyleSheet("color: #4CAF50;")
