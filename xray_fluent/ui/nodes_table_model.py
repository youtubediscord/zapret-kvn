from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QBrush, QColor

from ..country_flags import get_flag_icon
from ..models import Node

_RED_BRUSH = QBrush(QColor(220, 50, 50))
_GREEN_BRUSH = QBrush(QColor(76, 175, 80))
_ORANGE_BRUSH = QBrush(QColor(255, 152, 0))

_HEADERS = [
    "Имя",
    "Тип",
    "Сервер",
    "Порт",
    "Группа",
    "Теги",
    "Пинг",
    "Скорость",
    "Статус",
    "Последнее использование",
]


class NodesTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: list[Node] = []
        self._id_to_row: dict[str, int] = {}
        self._busy_ping_ids: set[str] = set()
        self._busy_speed_ids: set[str] = set()

    def set_nodes(self, nodes: list[Node]) -> None:
        self.beginResetModel()
        self._nodes = list(nodes)
        self._id_to_row = {node.id: row for row, node in enumerate(self._nodes)}
        self.endResetModel()

    def set_ping_busy(self, node_id: str, busy: bool) -> None:
        changed = False
        if busy:
            if node_id not in self._busy_ping_ids:
                self._busy_ping_ids.add(node_id)
                changed = True
        else:
            if node_id in self._busy_ping_ids:
                self._busy_ping_ids.discard(node_id)
                changed = True
        if changed:
            self._emit_cell_changed(node_id, 6)

    def clear_ping_busy(self) -> None:
        if not self._busy_ping_ids:
            return
        busy_ids = list(self._busy_ping_ids)
        self._busy_ping_ids.clear()
        for node_id in busy_ids:
            self._emit_cell_changed(node_id, 6)

    def set_speed_busy(self, node_id: str, busy: bool) -> None:
        changed = False
        if busy:
            if node_id not in self._busy_speed_ids:
                self._busy_speed_ids.add(node_id)
                changed = True
        else:
            if node_id in self._busy_speed_ids:
                self._busy_speed_ids.discard(node_id)
                changed = True
        if changed:
            self._emit_cell_changed(node_id, 7)

    def clear_speed_busy(self) -> None:
        if not self._busy_speed_ids:
            return
        busy_ids = list(self._busy_speed_ids)
        self._busy_speed_ids.clear()
        for node_id in busy_ids:
            self._emit_cell_changed(node_id, 7)

    def row_for_node(self, node_id: str) -> int | None:
        return self._id_to_row.get(node_id)

    def node_at_row(self, row: int) -> Node | None:
        if 0 <= row < len(self._nodes):
            return self._nodes[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._nodes)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(_HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(_HEADERS):
                return _HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._nodes):
            return None

        node = self._nodes[row]

        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return self._display_text(node, col)

        if role == Qt.ItemDataRole.DecorationRole and col == 0:
            return get_flag_icon(node.country_code)

        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip_text(node, col)

        if role == Qt.ItemDataRole.ForegroundRole:
            return self._foreground_brush(node, col)

        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 3, 6, 7, 8):
            return int(Qt.AlignmentFlag.AlignCenter)

        return None

    def refresh_ping(self, node_id: str) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        top_left = self.index(row, 0)
        bottom_right = self.index(row, 9)
        self.dataChanged.emit(
            top_left,
            bottom_right,
            [
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.ToolTipRole,
                Qt.ItemDataRole.ForegroundRole,
            ],
        )

    def refresh_speed(self, node_id: str) -> None:
        self._emit_cell_changed(node_id, 7)

    def refresh_alive_status(self, node_id: str) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        top_left = self.index(row, 0)
        bottom_right = self.index(row, 9)
        self.dataChanged.emit(
            top_left,
            bottom_right,
            [
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.ToolTipRole,
                Qt.ItemDataRole.ForegroundRole,
            ],
        )

    def _display_text(self, node: Node, col: int) -> str:
        if col == 0:
            return node.name or "Без имени"
        if col == 1:
            return node.scheme.upper()
        if col == 2:
            return node.server
        if col == 3:
            return str(node.port)
        if col == 4:
            return node.group
        if col == 5:
            return ", ".join(node.tags)
        if col == 6:
            if node.id in self._busy_ping_ids:
                return ""
            return "--" if node.ping_ms is None else f"{node.ping_ms} ms"
        if col == 7:
            if node.id in self._busy_speed_ids:
                return ""
            return "--" if node.speed_mbps is None else f"{node.speed_mbps:.1f} MB/s"
        if col == 8:
            text, _, _ = NodesTableModel._status_meta(node)
            return text
        if col == 9:
            return NodesTableModel._format_time(node.last_used_at)
        return ""

    def _tooltip_text(self, node: Node, col: int) -> str | None:
        if col == 6 and node.id in self._busy_ping_ids:
            return None
        if col == 7 and node.id in self._busy_speed_ids:
            return None
        if col == 6 and node.ping_ms is not None:
            return f"Пинг: {node.ping_ms} ms"
        if col == 8:
            _, tooltip, _ = NodesTableModel._status_meta(node)
            return tooltip
        return None

    @staticmethod
    def _foreground_brush(node: Node, col: int) -> QBrush | None:
        if node.is_alive is False:
            return _RED_BRUSH
        if col == 8:
            _, _, brush = NodesTableModel._status_meta(node)
            return brush
        return None

    @staticmethod
    def _status_meta(node: Node) -> tuple[str, str | None, QBrush | None]:
        if node.is_alive is None:
            return "--", None, None

        if node.ping_ms is not None and node.speed_mbps is None and node.is_alive:
            if node.speed_history:
                return "!", "Пинг есть, скорость нет — вероятно заблокирован провайдером", _ORANGE_BRUSH
            return "--", None, None

        if node.is_alive:
            return "OK", "Сервер работает", _GREEN_BRUSH

        return "X", "Сервер недоступен", _RED_BRUSH

    @staticmethod
    def _format_time(value: str | None) -> str:
        if not value:
            return ""
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return value

    def _emit_cell_changed(self, node_id: str, column: int) -> None:
        row = self._id_to_row.get(node_id)
        if row is None:
            return
        index = self.index(row, column)
        self.dataChanged.emit(
            index,
            index,
            [
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.ToolTipRole,
                Qt.ItemDataRole.ForegroundRole,
            ],
        )
