from __future__ import annotations

from datetime import datetime, timezone

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHBoxLayout, QHeaderView, QTableWidgetItem, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    ComboBox,
    FluentIcon as FIF,
    PushButton,
    SettingCardGroup,
    SmoothScrollArea,
    SubtitleLabel,
    TableWidget,
    TitleLabel,
)

from ..traffic_history import TrafficHistoryStorage, TrafficSession


class HistoryPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("history")
        self._storage: TrafficHistoryStorage | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = SmoothScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        scroll.setWidget(container)

        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("История трафика", container))

        # ── Controls row ──
        controls = QHBoxLayout()
        controls.setSpacing(12)

        self._period_combo = ComboBox(container)
        self._period_combo.addItem("7 дней", userData=7)
        self._period_combo.addItem("30 дней", userData=30)
        self._period_combo.addItem("Всё время", userData=3650)
        self._period_combo.setCurrentIndex(1)
        self._period_combo.setMinimumWidth(160)
        controls.addWidget(self._period_combo)

        self._refresh_btn = PushButton("Обновить", container)
        self._refresh_btn.setIcon(FIF.SYNC)
        controls.addWidget(self._refresh_btn)

        controls.addStretch()
        root.addLayout(controls)

        # ── Summary cards ──
        summary_row = QHBoxLayout()
        summary_row.setSpacing(16)

        self._total_down_label = TitleLabel("0 B", container)
        self._total_up_label = TitleLabel("0 B", container)
        self._session_count_label = BodyLabel("0 сессий", container)

        down_col = QVBoxLayout()
        down_col.addWidget(BodyLabel("Загрузка", container))
        down_col.addWidget(self._total_down_label)
        summary_row.addLayout(down_col)

        up_col = QVBoxLayout()
        up_col.addWidget(BodyLabel("Отдача", container))
        up_col.addWidget(self._total_up_label)
        summary_row.addLayout(up_col)

        count_col = QVBoxLayout()
        count_col.addWidget(BodyLabel("Сессий", container))
        count_col.addWidget(self._session_count_label)
        summary_row.addLayout(count_col)

        summary_row.addStretch()
        root.addLayout(summary_row)

        # ── Sessions table ──
        root.addWidget(BodyLabel("Сессии", container))

        self._sessions_table = TableWidget(container)
        self._sessions_table.setColumnCount(7)
        self._sessions_table.setHorizontalHeaderLabels([
            "Дата", "Сервер", "Режим", "Длительность", "Загрузка", "Отдача", "Процессы",
        ])
        self._sessions_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._sessions_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self._sessions_table.verticalHeader().setVisible(False)
        hdr = self._sessions_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._sessions_table.setMinimumHeight(300)
        root.addWidget(self._sessions_table)

        # ── Daily totals table ──
        root.addWidget(BodyLabel("Трафик по дням", container))

        self._daily_table = TableWidget(container)
        self._daily_table.setColumnCount(3)
        self._daily_table.setHorizontalHeaderLabels(["Дата", "Загрузка", "Отдача"])
        self._daily_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._daily_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self._daily_table.verticalHeader().setVisible(False)
        dhdr = self._daily_table.horizontalHeader()
        dhdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        dhdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        dhdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._daily_table.setMinimumHeight(180)
        root.addWidget(self._daily_table)

        # ── Per-process totals table ──
        root.addWidget(BodyLabel("Трафик по процессам (итого за период)", container))

        self._proc_table = TableWidget(container)
        self._proc_table.setColumnCount(4)
        self._proc_table.setHorizontalHeaderLabels(["Процесс", "Загрузка", "Отдача", "Маршрут"])
        self._proc_table.setEditTriggers(TableWidget.EditTrigger.NoEditTriggers)
        self._proc_table.setSelectionBehavior(TableWidget.SelectionBehavior.SelectRows)
        self._proc_table.verticalHeader().setVisible(False)
        phdr = self._proc_table.horizontalHeader()
        phdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        phdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        phdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        phdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._proc_table.setMinimumHeight(200)
        root.addWidget(self._proc_table)

        root.addStretch(1)

        # Signals
        self._period_combo.currentIndexChanged.connect(self._refresh)
        self._refresh_btn.clicked.connect(self._refresh)

    def set_storage(self, storage: TrafficHistoryStorage) -> None:
        self._storage = storage
        self._refresh()

    def _refresh(self) -> None:
        if not self._storage:
            return
        days = self._period_combo.currentData() or 30

        sessions = self._storage.get_sessions(days)
        sessions.sort(key=lambda s: s.started_at, reverse=True)

        # Summary
        total_up = sum(s.total_upload for s in sessions)
        total_down = sum(s.total_download for s in sessions)
        self._total_down_label.setText(_fmt_bytes(total_down))
        self._total_up_label.setText(_fmt_bytes(total_up))
        self._session_count_label.setText(f"{len(sessions)} сессий")

        # Sessions table
        self._sessions_table.setRowCount(len(sessions))
        for row, s in enumerate(sessions):
            # Date
            date_str = _fmt_datetime(s.started_at)
            self._sessions_table.setItem(row, 0, QTableWidgetItem(date_str))

            # Node
            self._sessions_table.setItem(row, 1, QTableWidgetItem(s.node_name))

            # Mode
            mode_text = {"xray": "Прокси", "singbox": "TUN (sing-box)", "tun2socks": "TUN (tun2socks)"}.get(s.mode, s.mode)
            mode_item = QTableWidgetItem(mode_text)
            if "tun" in s.mode.lower() or s.mode == "singbox":
                mode_item.setForeground(QColor("#3498db"))
            self._sessions_table.setItem(row, 2, mode_item)

            # Duration
            self._sessions_table.setItem(row, 3, QTableWidgetItem(_fmt_duration(s.started_at, s.ended_at)))

            # Download
            down_item = QTableWidgetItem(_fmt_bytes(s.total_download))
            if s.total_download > 0:
                down_item.setForeground(QColor("#2ecc71"))
            self._sessions_table.setItem(row, 4, down_item)

            # Upload
            self._sessions_table.setItem(row, 5, QTableWidgetItem(_fmt_bytes(s.total_upload)))

            # Processes
            procs = ", ".join(sorted(s.processes.keys())[:5])
            if len(s.processes) > 5:
                procs += f" (+{len(s.processes) - 5})"
            self._sessions_table.setItem(row, 6, QTableWidgetItem(procs))

        # Daily totals
        daily = self._storage.get_daily_totals(days)
        sorted_days = sorted(daily.items(), key=lambda kv: kv[0], reverse=True)
        self._daily_table.setRowCount(len(sorted_days))
        for row, (date_key, totals) in enumerate(sorted_days):
            self._daily_table.setItem(row, 0, QTableWidgetItem(date_key))
            down_item = QTableWidgetItem(_fmt_bytes(totals.get("download", 0)))
            if totals.get("download", 0) > 0:
                down_item.setForeground(QColor("#2ecc71"))
            self._daily_table.setItem(row, 1, down_item)
            self._daily_table.setItem(row, 2, QTableWidgetItem(_fmt_bytes(totals.get("upload", 0))))

        # Process totals
        proc_totals = self._storage.get_process_totals(days)
        sorted_procs = sorted(proc_totals.items(), key=lambda kv: kv[1]["download"], reverse=True)

        self._proc_table.setRowCount(len(sorted_procs))
        for row, (exe, stats) in enumerate(sorted_procs):
            self._proc_table.setItem(row, 0, QTableWidgetItem(exe))

            down_item = QTableWidgetItem(_fmt_bytes(int(stats["download"])))
            if int(stats["download"]) > 0:
                down_item.setForeground(QColor("#2ecc71"))
            self._proc_table.setItem(row, 1, down_item)

            self._proc_table.setItem(row, 2, QTableWidgetItem(_fmt_bytes(int(stats["upload"]))))

            route = str(stats.get("route", ""))
            route_text = {"proxy": "VPN", "direct": "Прямой", "mixed": "Смешанный"}.get(route, route)
            self._proc_table.setItem(row, 3, QTableWidgetItem(route_text))


def _fmt_bytes(b: int) -> str:
    value = float(max(0, int(b)))
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    unit_idx = 0
    while value >= 1024.0 and unit_idx < len(units) - 1:
        value /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(value)} {units[unit_idx]}"
    if unit_idx <= 2:
        return f"{value:.1f} {units[unit_idx]}"
    return f"{value:.2f} {units[unit_idx]}"


def _fmt_datetime(iso: str) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso).astimezone()
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return iso[:16]


def _fmt_duration(start: str, end: str | None) -> str:
    if not start:
        return ""
    try:
        s = datetime.fromisoformat(start)
        e = datetime.fromisoformat(end) if end else datetime.now(timezone.utc)
        delta = e - s
        total_sec = int(delta.total_seconds())
        if total_sec < 0:
            return ""
        hours, rem = divmod(total_sec, 3600)
        minutes, secs = divmod(rem, 60)
        if hours > 0:
            return f"{hours}ч {minutes}м"
        elif minutes > 0:
            return f"{minutes}м {secs}с"
        else:
            return f"{secs}с"
    except Exception:
        return ""
