from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QWidget
from qfluentwidgets import isDarkTheme

if TYPE_CHECKING:
    from PyQt6.QtGui import QPaintEvent, QMouseEvent

_MAX_POINTS = 60
_DETAIL_MAX_POINTS = 300

_COLOR_DOWN = QColor(0, 180, 255)
_COLOR_UP = QColor(0, 220, 120)
_COLOR_GRID = QColor(255, 255, 255, 20)
_COLOR_BG = QColor(0, 0, 0, 30)


def _format_speed_short(bps: float) -> str:
    if bps < 1024:
        return f"{int(bps)} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.0f} KB/s"
    if bps < 1024 * 1024 * 1024:
        return f"{bps / (1024 * 1024):.1f} MB/s"
    return f"{bps / (1024 * 1024 * 1024):.2f} GB/s"


class TrafficGraphWidget(QWidget):
    """Compact live traffic graph with download/upload lines."""

    clicked = pyqtSignal()

    def __init__(self, parent: QWidget | None = None, max_points: int = _MAX_POINTS):
        super().__init__(parent)
        self._max_points = max_points
        self._down_data: deque[float] = deque(maxlen=max_points)
        self._up_data: deque[float] = deque(maxlen=max_points)
        self.setMinimumHeight(80)
        self.setMaximumHeight(120)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Нажмите для подробного графика")

    def add_point(self, down_bps: float, up_bps: float) -> None:
        self._down_data.append(max(0.0, down_bps))
        self._up_data.append(max(0.0, up_bps))
        self.update()

    def clear_data(self) -> None:
        self._down_data.clear()
        self._up_data.clear()
        self.update()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        _draw_graph(painter, self.rect(), self._down_data, self._up_data, compact=True)
        painter.end()


class DetailTrafficGraphWidget(QWidget):
    """Larger traffic graph for the detail dialog."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._down_data: deque[float] = deque(maxlen=_DETAIL_MAX_POINTS)
        self._up_data: deque[float] = deque(maxlen=_DETAIL_MAX_POINTS)
        self.setMinimumHeight(300)
        self.setMinimumWidth(600)

    def set_data(self, down: deque[float], up: deque[float]) -> None:
        self._down_data = deque(down, maxlen=_DETAIL_MAX_POINTS)
        self._up_data = deque(up, maxlen=_DETAIL_MAX_POINTS)
        self.update()

    def add_point(self, down_bps: float, up_bps: float) -> None:
        self._down_data.append(max(0.0, down_bps))
        self._up_data.append(max(0.0, up_bps))
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        _draw_graph(painter, self.rect(), self._down_data, self._up_data, compact=False)
        painter.end()


class TrafficGraphDialog(QDialog):
    """Dialog showing a detailed traffic graph."""

    def __init__(self, down_data: deque[float], up_data: deque[float], parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("История трафика")
        self.setMinimumSize(700, 420)
        self.resize(800, 480)
        bg = "#2b2b2b" if isDarkTheme() else "#f3f3f3"
        self.setStyleSheet(f"TrafficGraphDialog {{ background-color: {bg}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        self.graph = DetailTrafficGraphWidget(self)
        self.graph.set_data(down_data, up_data)
        layout.addWidget(self.graph)

    def add_point(self, down_bps: float, up_bps: float) -> None:
        self.graph.add_point(down_bps, up_bps)


def _draw_graph(
    painter: QPainter,
    rect: QRectF | any,
    down_data: deque[float],
    up_data: deque[float],
    compact: bool,
) -> None:
    r = QRectF(rect)
    w, h = r.width(), r.height()

    # background
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(_COLOR_BG)
    painter.drawRoundedRect(r, 6, 6)

    margin_left = 8 if compact else 60
    margin_right = 8
    margin_top = 6 if compact else 24
    margin_bottom = 6 if compact else 24
    graph_x = r.x() + margin_left
    graph_y = r.y() + margin_top
    graph_w = w - margin_left - margin_right
    graph_h = h - margin_top - margin_bottom

    if graph_w < 10 or graph_h < 10:
        return

    # scale
    all_vals = list(down_data) + list(up_data)
    max_val = max(all_vals) if all_vals else 1.0
    max_val = max(max_val, 100.0)  # minimum scale 100 B/s
    max_val *= 1.15  # headroom

    # grid lines
    pen = QPen(_COLOR_GRID)
    pen.setWidthF(0.5)
    painter.setPen(pen)
    grid_lines = 3 if compact else 5
    for i in range(grid_lines + 1):
        y = graph_y + graph_h * i / grid_lines
        painter.drawLine(QPointF(graph_x, y), QPointF(graph_x + graph_w, y))

    # axis labels (detail mode only)
    if not compact:
        painter.setPen(QColor(180, 180, 180))
        font = QFont()
        font.setPixelSize(10)
        painter.setFont(font)
        for i in range(grid_lines + 1):
            y = graph_y + graph_h * i / grid_lines
            val = max_val * (1.0 - i / grid_lines)
            label = _format_speed_short(val)
            painter.drawText(QRectF(r.x() + 2, y - 8, margin_left - 6, 16),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, label)

        # time labels
        n = max(len(down_data), len(up_data), 1)
        for sec in [0, n // 4, n // 2, 3 * n // 4, n - 1]:
            if sec >= n:
                continue
            x = graph_x + graph_w * sec / max(n - 1, 1)
            ago = n - 1 - sec
            label = f"-{ago}с" if ago > 0 else "сейчас"
            painter.drawText(QRectF(x - 20, graph_y + graph_h + 4, 40, 16),
                             Qt.AlignmentFlag.AlignCenter, label)

        # title
        painter.setPen(QColor(200, 200, 200))
        font.setPixelSize(12)
        painter.setFont(font)
        painter.drawText(QRectF(graph_x, r.y() + 2, graph_w, 18),
                         Qt.AlignmentFlag.AlignCenter, "История трафика")

    # draw lines
    _draw_line(painter, graph_x, graph_y, graph_w, graph_h, down_data, max_val, _COLOR_DOWN, compact)
    _draw_line(painter, graph_x, graph_y, graph_w, graph_h, up_data, max_val, _COLOR_UP, compact)

    # legend
    if compact:
        font = QFont()
        font.setPixelSize(9)
        painter.setFont(font)
        lx = graph_x + 4
        ly = graph_y + 2

        painter.setPen(_COLOR_DOWN)
        painter.drawText(QPointF(lx, ly + 9), "↓ Загрузка")
        painter.setPen(_COLOR_UP)
        painter.drawText(QPointF(lx + 64, ly + 9), "↑ Выгрузка")
    else:
        font = QFont()
        font.setPixelSize(11)
        painter.setFont(font)
        lx = graph_x + graph_w - 120
        ly = r.y() + 4

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(_COLOR_DOWN)
        painter.drawRoundedRect(QRectF(lx, ly + 2, 10, 10), 2, 2)
        painter.setPen(_COLOR_DOWN)
        painter.drawText(QPointF(lx + 14, ly + 11), "Загрузка")

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(_COLOR_UP)
        painter.drawRoundedRect(QRectF(lx + 86, ly + 2, 10, 10), 2, 2)
        painter.setPen(_COLOR_UP)
        painter.drawText(QPointF(lx + 100, ly + 11), "Выгрузка")


def _draw_line(
    painter: QPainter,
    gx: float, gy: float, gw: float, gh: float,
    data: deque[float],
    max_val: float,
    color: QColor,
    compact: bool,
) -> None:
    n = len(data)
    if n < 2:
        return

    points: list[QPointF] = []
    for i, val in enumerate(data):
        x = gx + gw * i / (n - 1)
        y = gy + gh * (1.0 - min(val / max_val, 1.0))
        points.append(QPointF(x, y))

    # gradient fill
    gradient = QLinearGradient(0, gy, 0, gy + gh)
    fill_color = QColor(color)
    fill_color.setAlpha(50 if compact else 40)
    gradient.setColorAt(0.0, fill_color)
    fill_color.setAlpha(5)
    gradient.setColorAt(1.0, fill_color)

    fill_path = QPainterPath()
    fill_path.moveTo(QPointF(points[0].x(), gy + gh))
    for pt in points:
        fill_path.lineTo(pt)
    fill_path.lineTo(QPointF(points[-1].x(), gy + gh))
    fill_path.closeSubpath()

    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(gradient)
    painter.drawPath(fill_path)

    # line
    pen = QPen(color)
    pen.setWidthF(1.5 if compact else 2.0)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    line_path = QPainterPath()
    line_path.moveTo(points[0])
    for pt in points[1:]:
        line_path.lineTo(pt)
    painter.drawPath(line_path)
