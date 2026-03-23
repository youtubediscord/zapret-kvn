from __future__ import annotations

from datetime import datetime
from typing import cast

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt6.QtGui import QBrush, QColor, QCursor, QKeyEvent, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QHBoxLayout, QHeaderView,
    QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)
from qfluentwidgets import (
    ComboBox,
    FluentIcon as FIF,
    PrimaryToolButton,
    SearchLineEdit,
    SubtitleLabel,
    TableWidget,
    TransparentToolButton,
    VerticalSeparator,
)
from qfluentwidgets import RoundMenu, Action

from ..country_flags import get_flag_icon
from ..models import Node
from .node_detail_widget import NodeDetailWidget

_RED_BRUSH = QBrush(QColor(220, 50, 50))
_GREEN_BRUSH = QBrush(QColor(76, 175, 80))
_ORANGE_BRUSH = QBrush(QColor(255, 152, 0))

_SORT_KEYS = ["Вручную", "Имя", "Группа", "Тип", "Пинг", "Скорость", "Последнее использование"]

_COLUMN_SORT_MAP = {
    0: "Имя",
    1: "Тип",
    4: "Группа",
    6: "Пинг",
    7: "Скорость",
    9: "Последнее использование",
}


class NodesPage(QWidget):
    import_clipboard_requested = pyqtSignal()
    delete_requested = pyqtSignal(object)          # emits set[str] of node IDs
    ping_requested = pyqtSignal(object)             # emits set[str] or empty set
    speed_test_requested = pyqtSignal(object)       # emits set[str] of node IDs (or empty set for all)
    export_outbound_json_requested = pyqtSignal(str)
    export_runtime_json_requested = pyqtSignal(str)
    selected_node_changed = pyqtSignal(str)
    edit_node_requested = pyqtSignal(str)           # node_id
    bulk_edit_requested = pyqtSignal(object)        # set[str] of node_ids
    copy_link_requested = pyqtSignal(str)           # node_id
    reorder_requested = pyqtSignal(str, str)        # node_id, direction

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("nodes")

        self._nodes: list[Node] = []
        self._visible_node_ids: list[str] = []
        self._id_to_row: dict[str, int] = {}
        self._sort_ascending = True
        self._cached_groups: frozenset[str] = frozenset()
        self._cached_tags: frozenset[str] = frozenset()

        # Stack: page 0 = server list, page 1 = node detail
        self._stack = QStackedWidget(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self._stack)

        # --- Page 0: Server list ---
        list_page = QWidget()
        root = QVBoxLayout(list_page)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        title = SubtitleLabel("Серверы", self)
        root.addWidget(title)

        # --- Filter row ---
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self.search_edit = SearchLineEdit(self)
        self.search_edit.setPlaceholderText("Поиск серверов")
        filter_row.addWidget(self.search_edit, 1)

        self.group_filter = ComboBox(self)
        self.group_filter.setMinimumWidth(120)
        self.group_filter.addItem("Все группы")
        filter_row.addWidget(self.group_filter)

        self.tag_filter = ComboBox(self)
        self.tag_filter.setMinimumWidth(120)
        self.tag_filter.addItem("Все теги")
        filter_row.addWidget(self.tag_filter)

        filter_row.addWidget(VerticalSeparator(self))

        self.sort_combo = ComboBox(self)
        self.sort_combo.setMinimumWidth(110)
        for key in _SORT_KEYS:
            self.sort_combo.addItem(key)
        filter_row.addWidget(self.sort_combo)

        self.sort_order_btn = TransparentToolButton(FIF.UP, self)
        self.sort_order_btn.setToolTip("Порядок сортировки")
        filter_row.addWidget(self.sort_order_btn)

        root.addLayout(filter_row)

        # --- Action toolbar ---
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.import_btn = PrimaryToolButton(FIF.ADD, self)
        self.import_btn.setToolTip("Импорт из буфера (Ctrl+V)")
        toolbar.addWidget(self.import_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.edit_btn = TransparentToolButton(FIF.EDIT, self)
        self.edit_btn.setToolTip("Редактировать")
        toolbar.addWidget(self.edit_btn)

        self.bulk_edit_btn = TransparentToolButton(FIF.CHECKBOX, self)
        self.bulk_edit_btn.setToolTip("Массовое редактирование")
        self.bulk_edit_btn.setVisible(False)
        toolbar.addWidget(self.bulk_edit_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.ping_btn = TransparentToolButton(FIF.SEND, self)
        self.ping_btn.setToolTip("Пинг выбранных")
        toolbar.addWidget(self.ping_btn)

        self.ping_all_btn = TransparentToolButton(FIF.SYNC, self)
        self.ping_all_btn.setToolTip("Пинг всех")
        toolbar.addWidget(self.ping_all_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.speed_test_btn = TransparentToolButton(FIF.SPEED_HIGH, self)
        self.speed_test_btn.setToolTip("Тест скорости выбранных")
        toolbar.addWidget(self.speed_test_btn)

        self.speed_test_all_btn = TransparentToolButton(FIF.SPEED_MEDIUM, self)
        self.speed_test_all_btn.setToolTip("Тест скорости всех")
        toolbar.addWidget(self.speed_test_all_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.export_outbound_btn = TransparentToolButton(FIF.SAVE_AS, self)
        self.export_outbound_btn.setToolTip("Экспорт outbound JSON")
        toolbar.addWidget(self.export_outbound_btn)

        self.export_runtime_btn = TransparentToolButton(FIF.CODE, self)
        self.export_runtime_btn.setToolTip("Экспорт runtime конфига")
        toolbar.addWidget(self.export_runtime_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.delete_btn = TransparentToolButton(FIF.DELETE, self)
        self.delete_btn.setToolTip("Удалить выбранные")
        toolbar.addWidget(self.delete_btn)

        toolbar.addWidget(VerticalSeparator(self))

        self.move_up_btn = TransparentToolButton(FIF.UP, self)
        self.move_up_btn.setToolTip("Переместить вверх")
        self.move_up_btn.setEnabled(False)
        toolbar.addWidget(self.move_up_btn)

        self.move_down_btn = TransparentToolButton(FIF.DOWN, self)
        self.move_down_btn.setToolTip("Переместить вниз")
        self.move_down_btn.setEnabled(False)
        toolbar.addWidget(self.move_down_btn)

        toolbar.addStretch()

        root.addLayout(toolbar)

        # --- Table ---
        self.table = TableWidget(self)
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels(
            ["Имя", "Тип", "Сервер", "Порт", "Группа", "Теги", "Пинг", "Скорость", "Статус", "Последнее использование"]
        )
        vertical_header = cast(QHeaderView, self.table.verticalHeader())
        vertical_header.setVisible(False)

        horizontal_header = cast(QHeaderView, self.table.horizontalHeader())
        horizontal_header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self._on_header_clicked)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.setIconSize(QSize(20, 14))

        # Prevent deselection on empty area click
        self.table._orig_mousePressEvent = self.table.mousePressEvent
        def _no_deselect_mouse_press(event):
            if event.button() == Qt.MouseButton.LeftButton:
                index = self.table.indexAt(event.pos())
                if not index.isValid():
                    return
            self.table._orig_mousePressEvent(event)
        self.table.mousePressEvent = _no_deselect_mouse_press

        root.addWidget(self.table, 1)

        self._stack.addWidget(list_page)

        # --- Page 1: Node detail ---
        self._detail_widget = NodeDetailWidget(self)
        self._detail_widget.back_requested.connect(self._show_list)
        self._detail_widget.ping_node_requested.connect(lambda nid: self.ping_requested.emit({nid}))
        self._detail_widget.speed_test_node_requested.connect(lambda nid: self.speed_test_requested.emit({nid}))
        self._stack.addWidget(self._detail_widget)

        # --- Search debounce ---
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self._reload)

        # --- Connections ---
        self.search_edit.textChanged.connect(self._search_timer.start)
        self.group_filter.currentIndexChanged.connect(self._reload)
        self.tag_filter.currentIndexChanged.connect(self._reload)
        self.sort_combo.currentIndexChanged.connect(self._reload)
        self.sort_order_btn.clicked.connect(self._toggle_sort_order)
        self.import_btn.clicked.connect(self.import_clipboard_requested)
        self.edit_btn.clicked.connect(self._on_edit)
        self.bulk_edit_btn.clicked.connect(self._on_bulk_edit)
        self.ping_btn.clicked.connect(self._on_ping_selected)
        self.ping_all_btn.clicked.connect(self._on_ping_all)
        self.export_outbound_btn.clicked.connect(self._on_export_outbound)
        self.export_runtime_btn.clicked.connect(self._on_export_runtime)
        self.speed_test_btn.clicked.connect(self._on_speed_test_selected)
        self.speed_test_all_btn.clicked.connect(self._on_speed_test_all)
        self.delete_btn.clicked.connect(self._on_delete_selected)
        self.move_up_btn.clicked.connect(self._on_move_up)
        self.move_down_btn.clicked.connect(self._on_move_down)
        self.table.itemSelectionChanged.connect(self._emit_selection)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.customContextMenuRequested.connect(self._on_context_menu)

        # --- Keyboard shortcuts ---
        paste_shortcut = QShortcut(QKeySequence.StandardKey.Paste, self)
        paste_shortcut.activated.connect(self.import_clipboard_requested)

    # ── Public API ──

    def set_nodes(self, nodes: list[Node], selected_id: str | None = None) -> None:
        self._nodes = list(nodes)
        self._rebuild_filter_combos()
        self._reload()
        if selected_id:
            self._select_node(selected_id)

    def update_ping(self, node_id: str, ping_ms: int | None) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        text = "--" if ping_ms is None else f"{ping_ms} ms"
        item = QTableWidgetItem(text)
        if ping_ms is not None:
            item.setToolTip(f"Пинг: {ping_ms} ms")
        self.table.setItem(row, 6, item)

    def update_speed(self, node_id: str, speed_mbps: float | None) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        text = "--" if speed_mbps is None else f"{speed_mbps:.1f} MB/s"
        self.table.setItem(row, 7, QTableWidgetItem(text))

    def update_alive_status(self, node_id: str, is_alive: bool | None) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        node = next((n for n in self._nodes if n.id == node_id), None)
        status_item = self._make_status_item(node) if node else QTableWidgetItem("--")
        if is_alive == False:
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    item.setForeground(_RED_BRUSH)
        self.table.setItem(row, 8, status_item)

    def refresh_detail(self) -> None:
        """Refresh detail view if it is currently visible."""
        if self._stack.currentIndex() == 1:
            self._detail_widget.refresh()

    # ── Filter combos ──

    def _rebuild_filter_combos(self) -> None:
        new_groups = frozenset(n.group for n in self._nodes if n.group)
        new_tags: set[str] = set()
        for n in self._nodes:
            new_tags.update(n.tags)
        new_tags_frozen = frozenset(new_tags)

        if new_groups == self._cached_groups and new_tags_frozen == self._cached_tags:
            return
        self._cached_groups = new_groups
        self._cached_tags = new_tags_frozen

        prev_group = self.group_filter.currentText()
        prev_tag = self.tag_filter.currentText()

        self.group_filter.blockSignals(True)
        self.group_filter.clear()
        self.group_filter.addItem("Все группы")
        for g in sorted(new_groups):
            self.group_filter.addItem(g)
        idx = self.group_filter.findText(prev_group)
        self.group_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.group_filter.blockSignals(False)

        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        self.tag_filter.addItem("Все теги")
        for t in sorted(new_tags_frozen):
            self.tag_filter.addItem(t)
        idx = self.tag_filter.findText(prev_tag)
        self.tag_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.tag_filter.blockSignals(False)

    # ── Reload / filter / sort ──

    def _reload(self) -> None:
        prev_selected = self._selected_ids()
        query = self.search_edit.text().strip().lower()
        group_filter = self.group_filter.currentText()
        tag_filter = self.tag_filter.currentText()

        filtered = []
        for node in self._nodes:
            if group_filter != "Все группы" and node.group != group_filter:
                continue
            if tag_filter != "Все теги" and tag_filter not in node.tags:
                continue
            if query:
                haystack = " ".join(
                    [node.name, node.scheme, node.server, node.group, " ".join(node.tags)]
                ).lower()
                if query not in haystack:
                    continue
            filtered.append(node)

        sort_key = self.sort_combo.currentText()
        filtered = self._sort_nodes(filtered, sort_key, self._sort_ascending)

        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        self.table.setRowCount(len(filtered))
        self._visible_node_ids = []
        self._id_to_row = {}

        for row, node in enumerate(filtered):
            self._visible_node_ids.append(node.id)
            self._id_to_row[node.id] = row
            name_item = QTableWidgetItem(node.name or "Без имени")
            icon = get_flag_icon(node.country_code)
            if icon:
                name_item.setIcon(icon)
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(node.scheme.upper()))
            self.table.setItem(row, 2, QTableWidgetItem(node.server))
            self.table.setItem(row, 3, QTableWidgetItem(str(node.port)))
            self.table.setItem(row, 4, QTableWidgetItem(node.group))
            self.table.setItem(row, 5, QTableWidgetItem(", ".join(node.tags)))

            # Column 6 — Ping
            ping_text = "--" if node.ping_ms is None else f"{node.ping_ms} ms"
            ping_item = QTableWidgetItem(ping_text)
            if node.ping_ms is not None:
                ping_item.setToolTip(f"Пинг: {node.ping_ms} ms")
            if node.is_alive == False:
                ping_item.setForeground(_RED_BRUSH)
            self.table.setItem(row, 6, ping_item)

            # Column 7 — Speed
            speed_text = "--" if node.speed_mbps is None else f"{node.speed_mbps:.1f} MB/s"
            self.table.setItem(row, 7, QTableWidgetItem(speed_text))

            # Column 8 — Status
            status_item = self._make_status_item(node)
            self.table.setItem(row, 8, status_item)

            # Column 9 — Last used
            self.table.setItem(row, 9, QTableWidgetItem(self._format_time(node.last_used_at)))

            # Red highlight for dead servers
            if node.is_alive == False:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item:
                        item.setForeground(_RED_BRUSH)

        self.table.blockSignals(False)
        self.table.setUpdatesEnabled(True)

        if prev_selected:
            for row, nid in enumerate(self._visible_node_ids):
                if nid in prev_selected:
                    self.table.selectRow(row)
                    break

    @staticmethod
    def _sort_nodes(nodes: list[Node], key: str, ascending: bool) -> list[Node]:
        if key == "Вручную":
            return sorted(nodes, key=lambda n: n.sort_order, reverse=not ascending)
        if key == "Имя":
            return sorted(nodes, key=lambda n: n.name.lower(), reverse=not ascending)
        if key == "Группа":
            return sorted(nodes, key=lambda n: n.group.lower(), reverse=not ascending)
        if key == "Тип":
            return sorted(nodes, key=lambda n: n.scheme.lower(), reverse=not ascending)
        if key == "Пинг":
            none_val = float("inf") if ascending else float("-inf")
            return sorted(
                nodes,
                key=lambda n: n.ping_ms if n.ping_ms is not None else none_val,
                reverse=not ascending,
            )
        if key == "Скорость":
            none_val = float("inf") if ascending else float("-inf")
            return sorted(
                nodes,
                key=lambda n: n.speed_mbps if n.speed_mbps is not None else none_val,
                reverse=not ascending,
            )
        if key == "Последнее использование":
            return sorted(nodes, key=lambda n: n.last_used_at or "", reverse=not ascending)
        return nodes

    def _toggle_sort_order(self) -> None:
        self._sort_ascending = not self._sort_ascending
        self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
        self._reload()

    def _on_header_clicked(self, logical_index: int) -> None:
        sort_key = _COLUMN_SORT_MAP.get(logical_index)
        if sort_key is None:
            return
        idx = self.sort_combo.findText(sort_key)
        if idx < 0:
            return
        if self.sort_combo.currentIndex() == idx:
            self._sort_ascending = not self._sort_ascending
            self.sort_order_btn.setIcon(FIF.UP if self._sort_ascending else FIF.DOWN)
            self._reload()
        else:
            self._sort_ascending = True
            self.sort_order_btn.setIcon(FIF.UP)
            self.sort_combo.setCurrentIndex(idx)

    # ── Selection helpers ──

    def _selected_ids(self) -> set[str]:
        model = self.table.selectionModel()
        if model is None:
            return set()
        ids: set[str] = set()
        for index in model.selectedRows():
            row = index.row()
            if 0 <= row < len(self._visible_node_ids):
                ids.add(self._visible_node_ids[row])
        return ids

    def _select_node(self, node_id: str) -> None:
        row = self._id_to_row.get(node_id)
        if row is not None:
            self.table.selectRow(row)

    def _emit_selection(self) -> None:
        ids = self._selected_ids()
        self.bulk_edit_btn.setVisible(len(ids) > 1)
        is_manual = self.sort_combo.currentText() == "Вручную"
        self.move_up_btn.setEnabled(is_manual and len(ids) == 1)
        self.move_down_btn.setEnabled(is_manual and len(ids) == 1)
        if len(ids) == 1:
            self.selected_node_changed.emit(next(iter(ids)))

    # ── Button handlers ──

    def _on_move_up(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "up")

    def _on_move_down(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.reorder_requested.emit(next(iter(ids)), "down")

    def _on_edit(self) -> None:
        ids = self._selected_ids()
        if len(ids) == 1:
            self.edit_node_requested.emit(next(iter(ids)))

    def _on_bulk_edit(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.bulk_edit_requested.emit(ids)

    def _on_ping_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.ping_requested.emit(ids)

    def _on_ping_all(self) -> None:
        self.ping_requested.emit(set())

    def _on_speed_test_selected(self) -> None:
        ids = self._selected_ids()
        if ids:
            self.speed_test_requested.emit(ids)

    def _on_speed_test_all(self) -> None:
        self.speed_test_requested.emit(set())

    def _on_delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        from qfluentwidgets import MessageBox
        count = len(ids)
        title = "Удаление серверов" if count > 1 else "Удаление сервера"
        msg = f"Удалить {count} серверов?" if count > 1 else "Удалить выбранный сервер?"
        box = MessageBox(title, msg, self.window())
        box.yesButton.setText("Удалить")
        box.cancelButton.setText("Отмена")
        if box.exec():
            self.delete_requested.emit(ids)

    def _on_export_outbound(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_outbound_json_requested.emit(next(iter(ids)))

    def _on_export_runtime(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 1:
            return
        self.export_runtime_json_requested.emit(next(iter(ids)))

    # ── Double-click / context menu ──

    def _on_double_click(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._visible_node_ids):
            node_id = self._visible_node_ids[row]
            node = next((n for n in self._nodes if n.id == node_id), None)
            if node:
                self._show_detail(node)

    def _on_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        clicked_row = item.row()
        if clicked_row < 0 or clicked_row >= len(self._visible_node_ids):
            return

        clicked_id = self._visible_node_ids[clicked_row]
        current_ids = self._selected_ids()
        if clicked_id not in current_ids:
            self.table.clearSelection()
            self.table.selectRow(clicked_row)
            ids = {clicked_id}
        else:
            ids = current_ids

        menu = RoundMenu(parent=self)
        count = len(ids)

        if count == 1:
            node_id = next(iter(ids))
            edit_action = Action("Редактировать", self)
            edit_action.triggered.connect(lambda: self.edit_node_requested.emit(node_id))
            menu.addAction(edit_action)

            copy_action = Action("Копировать ссылку", self)
            copy_action.triggered.connect(lambda: self._copy_node_link(node_id))
            menu.addAction(copy_action)
        else:
            copy_action = Action(f"Копировать {count} ссылок", self)
            copy_action.triggered.connect(lambda: self._copy_multiple_links(ids))
            menu.addAction(copy_action)

        bulk_action = Action("Массовое редактирование", self)
        bulk_action.triggered.connect(lambda: self.bulk_edit_requested.emit(ids))
        menu.addAction(bulk_action)

        menu.addSeparator()

        ping_action = Action(f"Пинг ({count})" if count > 1 else "Пинг", self)
        ping_action.triggered.connect(lambda: self.ping_requested.emit(ids))
        menu.addAction(ping_action)

        speed_action = Action(f"Тест скорости ({count})" if count > 1 else "Тест скорости", self)
        speed_action.triggered.connect(lambda: self.speed_test_requested.emit(ids))
        menu.addAction(speed_action)

        menu.addSeparator()

        delete_label = f"Удалить {count} серверов" if count > 1 else "Удалить"
        delete_action = Action(delete_label, self)
        delete_action.triggered.connect(lambda: self.delete_requested.emit(ids))
        menu.addAction(delete_action)

        if count == 1 and self.sort_combo.currentText() == "Вручную":
            node_id = next(iter(ids))
            menu.addSeparator()
            move_top = Action("В начало списка", self)
            move_top.triggered.connect(lambda: self.reorder_requested.emit(node_id, "top"))
            menu.addAction(move_top)
            move_bottom = Action("В конец списка", self)
            move_bottom.triggered.connect(lambda: self.reorder_requested.emit(node_id, "bottom"))
            menu.addAction(move_bottom)

        menu.exec(QCursor.pos())

    # ── Navigation (list / detail) ──

    def _show_detail(self, node: Node) -> None:
        self._detail_widget.set_node(node)
        self._stack.setCurrentIndex(1)

    def _show_list(self) -> None:
        self._stack.setCurrentIndex(0)

    # ── Utilities ──

    def _copy_node_link(self, node_id: str) -> None:
        for node in self._nodes:
            if node.id == node_id and node.link:
                clipboard = QApplication.clipboard()
                if clipboard is not None:
                    clipboard.setText(node.link)
                break

    def _copy_multiple_links(self, node_ids: set[str]) -> None:
        links: list[str] = []
        for vid in self._visible_node_ids:
            if vid in node_ids:
                for node in self._nodes:
                    if node.id == vid and node.link:
                        links.append(node.link)
                        break
        if links:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText("\n".join(links))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Delete:
            self._on_delete_selected()
            return
        if event.matches(QKeySequence.StandardKey.Copy):
            ids = self._selected_ids()
            if ids:
                if len(ids) == 1:
                    self._copy_node_link(next(iter(ids)))
                else:
                    self._copy_multiple_links(ids)
            return
        super().keyPressEvent(event)

    @staticmethod
    def _make_status_item(node: Node) -> QTableWidgetItem:
        if node.is_alive is None:
            item = QTableWidgetItem("--")
        elif node.ping_ms is not None and node.speed_mbps is None and node.is_alive:
            if node.speed_history:
                # Тест скорости запускался и провалился
                item = QTableWidgetItem("!")
                item.setToolTip("Пинг есть, скорость нет — вероятно заблокирован провайдером")
                item.setForeground(_ORANGE_BRUSH)
            else:
                # Тест скорости не запускался — нейтральный статус
                item = QTableWidgetItem("--")
        elif node.is_alive:
            item = QTableWidgetItem("OK")
            item.setToolTip("Сервер работает")
            item.setForeground(_GREEN_BRUSH)
        else:
            item = QTableWidgetItem("X")
            item.setToolTip("Сервер недоступен")
            item.setForeground(_RED_BRUSH)
        return item

    @staticmethod
    def _format_time(value: str | None) -> str:
        if not value:
            return ""
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value
