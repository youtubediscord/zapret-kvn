from __future__ import annotations

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import BodyLabel, PlainTextEdit, PrimaryPushButton, PushButton, SearchLineEdit, SubtitleLabel


class LogsPage(QWidget):
    clear_requested = pyqtSignal()
    export_diag_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("logs")
        self._lines: list[str] = []
        self._pending_lines: list[str] = []
        self._full_refresh_needed = False

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Логи и диагностика", self))

        toolbar = QHBoxLayout()
        self.search = SearchLineEdit(self)
        self.search.setPlaceholderText("Фильтр логов")
        self.clear_btn = PushButton("Очистить", self)
        self.export_btn = PrimaryPushButton("Экспорт диагностики", self)

        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.export_btn)
        root.addLayout(toolbar)

        root.addWidget(BodyLabel("Логи работы", self))
        self.log_edit = PlainTextEdit(self)
        self.log_edit.setReadOnly(True)
        self.log_edit.document().setMaximumBlockCount(2000)
        root.addWidget(self.log_edit, 1)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(200)
        self._refresh_timer.timeout.connect(self._flush_updates)

        self.search.textChanged.connect(self._schedule_full_refresh)
        self.clear_btn.clicked.connect(self.clear_requested)
        self.export_btn.clicked.connect(self.export_diag_requested)

    def append_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) > 5000:
            self._lines = self._lines[-5000:]
        self._pending_lines.append(line)
        if self.search.text().strip():
            self._full_refresh_needed = True
        self._schedule_flush()

    def set_lines(self, lines: list[str]) -> None:
        self._lines = list(lines)
        self._pending_lines.clear()
        self._schedule_full_refresh()

    def clear_view(self) -> None:
        self._lines = []
        self._pending_lines.clear()
        self._full_refresh_needed = False
        self._refresh_timer.stop()
        self.log_edit.clear()

    def _schedule_flush(self) -> None:
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _schedule_full_refresh(self) -> None:
        self._full_refresh_needed = True
        self._schedule_flush()

    def _flush_updates(self) -> None:
        query = self.search.text().strip().lower()
        if self._full_refresh_needed or query:
            if not query:
                data = self._lines
            else:
                data = [line for line in self._lines if query in line.lower()]
            self.log_edit.setPlainText("\n".join(data[-2000:]))
        else:
            if self._pending_lines:
                self.log_edit.appendPlainText("\n".join(self._pending_lines))
        self._pending_lines.clear()
        self._full_refresh_needed = False
        vbar = self.log_edit.verticalScrollBar()
        vbar.setValue(vbar.maximum())
