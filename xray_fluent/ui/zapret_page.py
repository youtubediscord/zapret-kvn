"""Zapret (DPI bypass) management page — preset table + editor subpage."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView,
    QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    IndeterminateProgressBar,
    PrimaryToolButton,
    SubtitleLabel,
    TableWidget,
    TransparentToolButton,
    VerticalSeparator,
)
from qfluentwidgets import RoundMenu, Action

from ..zapret_manager import PresetInfo, ZapretManager
from .preset_edit_widget import PresetEditWidget


class ZapretPage(QWidget):
    start_requested = pyqtSignal(str)   # preset name
    stop_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("zapret")

        self._presets: list[PresetInfo] = []
        self._running = False
        self._active_preset = ""

        # ── Stack: page 0 = list, page 1 = editor ──
        self._stack = QStackedWidget(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._stack)

        # ══════════════ Page 0: Preset list ══════════════
        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Обход блокировок (zapret)", list_page))

        # Info card
        info_card = CardWidget(list_page)
        info_lay = QVBoxLayout(info_card)
        info_lay.setContentsMargins(16, 12, 16, 12)
        info_lay.setSpacing(4)
        info_lay.addWidget(BodyLabel(
            "Zapret (winws2) — инструмент обхода DPI-блокировок.\n"
            "Выберите пресет и нажмите «Запустить». Работает независимо от VPN/прокси.",
            info_card,
        ))
        info_lay.addWidget(CaptionLabel(
            "Требуются права администратора. Файлы zapret должны находиться в папке zapret/ рядом с приложением.",
            info_card,
        ))
        root.addWidget(info_card)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.add_btn = PrimaryToolButton(FIF.ADD, list_page)
        self.add_btn.setToolTip("Создать новый пресет")
        toolbar.addWidget(self.add_btn)

        self.import_btn = TransparentToolButton(FIF.FOLDER, list_page)
        self.import_btn.setToolTip("Импорт из файла")
        toolbar.addWidget(self.import_btn)

        toolbar.addWidget(VerticalSeparator(list_page))

        self.delete_btn = TransparentToolButton(FIF.DELETE, list_page)
        self.delete_btn.setToolTip("Удалить пресет")
        toolbar.addWidget(self.delete_btn)

        self.refresh_btn = TransparentToolButton(FIF.SYNC, list_page)
        self.refresh_btn.setToolTip("Обновить список")
        toolbar.addWidget(self.refresh_btn)

        toolbar.addStretch()

        toolbar.addWidget(VerticalSeparator(list_page))

        self.start_btn = TransparentToolButton(FIF.PLAY_SOLID, list_page)
        self.start_btn.setToolTip("Запустить выбранный пресет")
        toolbar.addWidget(self.start_btn)

        self.stop_btn = TransparentToolButton(FIF.PAUSE_BOLD, list_page)
        self.stop_btn.setToolTip("Остановить zapret")
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)

        root.addLayout(toolbar)

        # Status bar
        status_card = CardWidget(list_page)
        status_lay = QHBoxLayout(status_card)
        status_lay.setContentsMargins(16, 8, 16, 8)
        self.status_label = BodyLabel("Остановлен", status_card)
        status_lay.addWidget(self.status_label, 1)
        self.progress = IndeterminateProgressBar(status_card)
        self.progress.setFixedHeight(3)
        self.progress.hide()
        status_lay.addWidget(self.progress)
        root.addWidget(status_card)

        # Table
        self.table = TableWidget(list_page)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Имя", "Описание", "Аргументов", "Изменён"])
        v_header = cast(QHeaderView, self.table.verticalHeader())
        v_header.setVisible(False)
        h_header = cast(QHeaderView, self.table.horizontalHeader())
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        root.addWidget(self.table, 1)

        self._stack.addWidget(list_page)

        # ══════════════ Page 1: Editor ══════════════
        self._editor = PresetEditWidget(self)
        self._stack.addWidget(self._editor)

        # ── Signals ──
        self.add_btn.clicked.connect(self._on_create)
        self.import_btn.clicked.connect(self._on_import)
        self.delete_btn.clicked.connect(self._on_delete)
        self.refresh_btn.clicked.connect(self.refresh_presets)
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        self._editor.back_requested.connect(self._show_list)
        self._editor.save_requested.connect(self._on_save_preset)

    # ── Public API ──

    def set_presets(self, infos: list[PresetInfo], selected: str = "") -> None:
        self._presets = list(infos)
        self._reload_table(selected)

    def set_running(self, running: bool, preset_name: str = "") -> None:
        self._running = running
        if running:
            self._active_preset = preset_name
            self.status_label.setText(f"Работает: {preset_name}")
            self.status_label.setStyleSheet("color: #4CAF50;")
            self.progress.show()
            self.progress.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
        else:
            self._active_preset = ""
            self.status_label.setText("Остановлен")
            self.status_label.setStyleSheet("")
            self.progress.stop()
            self.progress.hide()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
        self._reload_table()

    def set_error(self, message: str) -> None:
        self.status_label.setText(f"Ошибка: {message}")
        self.status_label.setStyleSheet("color: #F44336;")
        self.set_running(False)
        self.status_label.setStyleSheet("color: #F44336;")

    def current_preset(self) -> str:
        row = self.table.currentRow()
        if 0 <= row < len(self._presets):
            return self._presets[row].name
        return ""

    def refresh_presets(self) -> None:
        selected = self.current_preset()
        self._presets = ZapretManager.list_preset_infos()
        self._reload_table(selected)

    # ── Table ──

    def _reload_table(self, select_name: str = "") -> None:
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        self.table.setRowCount(len(self._presets))

        select_row = -1
        for row, p in enumerate(self._presets):
            name_item = QTableWidgetItem(p.name)
            desc_item = QTableWidgetItem(p.description)
            args_item = QTableWidgetItem(str(p.arg_count))
            mod_item = QTableWidgetItem(self._format_date(p.modified))

            # Highlight active preset
            if self._running and p.name == self._active_preset:
                green = QBrush(QColor(76, 175, 80))
                for item in (name_item, desc_item, args_item, mod_item):
                    item.setForeground(green)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, desc_item)
            self.table.setItem(row, 2, args_item)
            self.table.setItem(row, 3, mod_item)

            if p.name == select_name:
                select_row = row

        self.table.blockSignals(False)
        self.table.setUpdatesEnabled(True)

        if select_row >= 0:
            self.table.selectRow(select_row)

    @staticmethod
    def _format_date(iso: str) -> str:
        if not iso:
            return ""
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(iso)
            return dt.strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            return iso

    # ── Handlers ──

    def _on_start(self) -> None:
        name = self.current_preset()
        if name:
            self.start_requested.emit(name)

    def _on_stop(self) -> None:
        self.stop_requested.emit()

    def _on_double_click(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._presets):
            self._open_editor(self._presets[row])

    def _on_create(self) -> None:
        self._editor.set_preset("", "", "")
        self._stack.setCurrentIndex(1)

    def _on_import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Импорт пресета", "", "Текстовые файлы (*.txt);;Все файлы (*)"
        )
        if path:
            info = ZapretManager.import_preset(Path(path))
            if info:
                self.refresh_presets()
                self._reload_table(info.name)

    def _on_delete(self) -> None:
        name = self.current_preset()
        if not name:
            return
        from qfluentwidgets import MessageBox
        box = MessageBox("Удаление пресета", f"Удалить «{name}»?", self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            if self._running and name == self._active_preset:
                self.stop_requested.emit()
            ZapretManager.delete_preset(name)
            self.refresh_presets()

    def _on_save_preset(self, name: str, description: str, content: str) -> None:
        ZapretManager.save_preset(name, content, description)
        self.refresh_presets()
        self._reload_table(name)
        self._show_list()

    def _open_editor(self, info: PresetInfo) -> None:
        content = ZapretManager.read_preset(info.name)
        self._editor.set_preset(info.name, info.description, content,
                                info.created, info.modified)
        self._stack.setCurrentIndex(1)

    def _show_list(self) -> None:
        self._stack.setCurrentIndex(0)

    def _on_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        if row < 0 or row >= len(self._presets):
            return

        preset = self._presets[row]
        self.table.selectRow(row)

        menu = RoundMenu(parent=self)

        edit_action = Action("Редактировать", self)
        edit_action.triggered.connect(lambda: self._open_editor(preset))
        menu.addAction(edit_action)

        start_action = Action("Запустить", self)
        start_action.triggered.connect(lambda: self.start_requested.emit(preset.name))
        menu.addAction(start_action)

        menu.addSeparator()

        delete_action = Action("Удалить", self)
        delete_action.triggered.connect(self._on_delete)
        menu.addAction(delete_action)

        menu.exec(QCursor.pos())
