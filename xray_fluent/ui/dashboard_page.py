from __future__ import annotations

from collections import deque

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    BreadcrumbBar,
    CaptionLabel,
    CardWidget,
    ComboBox,
    FluentIcon as FIF,
    PrimaryPushButton,
    SmoothScrollArea,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
)

from ..models import AppSettings, Node, RoutingSettings
from .traffic_graph import DetailTrafficGraphWidget, TrafficGraphWidget


def _format_speed(value_bps: float) -> str:
    value = max(0.0, value_bps)
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    unit_index = 0
    while value >= 1024.0 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _format_latency(value_ms: int | None) -> str:
    if value_ms is None:
        return "--"
    return f"{value_ms} ms"


def _mode_title(mode: str) -> str:
    mapping = {
        "global": "Глобальный",
        "rule": "Правила",
        "direct": "Прямой",
    }
    return mapping.get(mode, mode.title() or "Неизвестно")


class DashboardPage(QWidget):
    toggle_connection_requested = pyqtSignal()
    node_selected = pyqtSignal(str)
    mode_changed = pyqtSignal(str)
    tun_toggled = pyqtSignal(bool)
    proxy_toggled = pyqtSignal(bool)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("dashboard")

        self._nodes: list[Node] = []
        self._node_ids: list[str] = []
        self._selected_node: Node | None = None
        self._connected = False
        self._mode = "rule"
        self._settings = AppSettings()
        self._routing = RoutingSettings()
        self._selected_latency_ms: int | None = None
        self._live_rtt_ms: int | None = None
        self._last_down_bps = 0.0
        self._last_up_bps = 0.0
        self._peak_bps = 0.0
        self._down_history: deque[float] = deque(maxlen=300)
        self._up_history: deque[float] = deque(maxlen=300)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(30)
        self._refresh_timer.timeout.connect(self._do_refresh_dashboard)

        # ── Outer layout with QStackedWidget ──────────────────
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._stack = QStackedWidget(self)
        outer.addWidget(self._stack)

        # ── Page 0: main dashboard ────────────────────────────
        main_page = QWidget()
        main_page.setStyleSheet("QWidget { background: transparent; }")
        self._stack.addWidget(main_page)

        main_outer = QVBoxLayout(main_page)
        main_outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = SmoothScrollArea(main_page)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        main_outer.addWidget(self._scroll)

        container = QWidget()
        container.setStyleSheet("QWidget { background: transparent; }")
        self._scroll.setWidget(container)

        root = QVBoxLayout(container)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Панель управления", container))
        self.summary_label = CaptionLabel("Краткий обзор подключения, профиля, трафика и маршрутизации.", self)
        self.summary_label.setWordWrap(True)
        root.addWidget(self.summary_label)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        # ── Connection card ───────────────────────────────────
        self.connection_card = CardWidget(self)
        connection_layout = QVBoxLayout(self.connection_card)
        connection_layout.setContentsMargins(18, 16, 18, 16)
        connection_layout.setSpacing(6)
        connection_layout.addWidget(StrongBodyLabel("Подключение", self.connection_card))
        self.connection_state_label = SubtitleLabel("Ожидание", self.connection_card)
        self.connection_engine_label = BodyLabel("Системный прокси", self.connection_card)
        self.connection_status_label = CaptionLabel("Прокси остановлен", self.connection_card)
        self.connection_target_label = CaptionLabel("Активный профиль не выбран", self.connection_card)
        self.connection_target_label.setWordWrap(True)
        connection_layout.addWidget(self.connection_state_label)
        connection_layout.addWidget(self.connection_engine_label)

        switches_row = QHBoxLayout()
        switches_row.setSpacing(20)
        tun_label = CaptionLabel("VPN (TUN)", self.connection_card)
        self.tun_switch = SwitchButton(self.connection_card)
        self.tun_switch.setOnText("Вкл")
        self.tun_switch.setOffText("Выкл")
        switches_row.addWidget(tun_label)
        switches_row.addWidget(self.tun_switch)
        switches_row.addSpacing(12)
        proxy_label = CaptionLabel("Сист. прокси", self.connection_card)
        self.proxy_switch = SwitchButton(self.connection_card)
        self.proxy_switch.setOnText("Вкл")
        self.proxy_switch.setOffText("Выкл")
        switches_row.addWidget(proxy_label)
        switches_row.addWidget(self.proxy_switch)
        switches_row.addStretch(1)
        connection_layout.addLayout(switches_row)

        # Toggle button inside connection card
        self.toggle_btn = PrimaryPushButton(FIF.PLAY_SOLID, "Запустить прокси", self.connection_card)
        connection_layout.addWidget(self.toggle_btn)

        connection_layout.addStretch(1)
        connection_layout.addWidget(self.connection_status_label)
        connection_layout.addWidget(self.connection_target_label)

        # ── Profile card ──────────────────────────────────────
        self.profile_card = CardWidget(self)
        profile_layout = QVBoxLayout(self.profile_card)
        profile_layout.setContentsMargins(18, 16, 18, 16)
        profile_layout.setSpacing(8)
        profile_layout.addWidget(StrongBodyLabel("Активный профиль", self.profile_card))
        self.node_combo = ComboBox(self.profile_card)
        profile_layout.addWidget(self.node_combo)
        self.profile_name_label = BodyLabel("Профиль не выбран", self.profile_card)
        self.profile_endpoint_label = CaptionLabel("Сначала импортируйте или выберите узел", self.profile_card)
        self.profile_group_label = CaptionLabel("Группа: --", self.profile_card)
        self.profile_latency_label = CaptionLabel("Задержка: --", self.profile_card)
        self.profile_endpoint_label.setWordWrap(True)
        profile_layout.addWidget(self.profile_name_label)
        profile_layout.addStretch(1)
        profile_layout.addWidget(self.profile_endpoint_label)
        profile_layout.addWidget(self.profile_group_label)
        profile_layout.addWidget(self.profile_latency_label)

        # ── Traffic card ──────────────────────────────────────
        self.traffic_card = CardWidget(self)
        traffic_layout = QVBoxLayout(self.traffic_card)
        traffic_layout.setContentsMargins(18, 16, 18, 16)
        traffic_layout.setSpacing(6)
        traffic_layout.addWidget(StrongBodyLabel("Трафик", self.traffic_card))
        self.traffic_down_label = BodyLabel("Загрузка: 0 B/s", self.traffic_card)
        self.traffic_up_label = BodyLabel("Выгрузка: 0 B/s", self.traffic_card)
        self.traffic_rtt_label = BodyLabel("RTT: --", self.traffic_card)
        self.traffic_graph = TrafficGraphWidget(self.traffic_card)
        self.traffic_graph.clicked.connect(self._show_traffic_page)
        self.traffic_peak_label = CaptionLabel("Пик: 0 B/s", self.traffic_card)
        traffic_layout.addWidget(self.traffic_down_label)
        traffic_layout.addWidget(self.traffic_up_label)
        traffic_layout.addWidget(self.traffic_rtt_label)
        traffic_layout.addWidget(self.traffic_graph, 1)
        traffic_layout.addWidget(self.traffic_peak_label)

        # ── Process traffic table (TUN mode only) ────────────
        self._proc_traffic_card = CardWidget(self)
        proc_layout = QVBoxLayout(self._proc_traffic_card)
        proc_layout.setContentsMargins(18, 16, 18, 16)
        proc_layout.setSpacing(6)
        proc_layout.addWidget(StrongBodyLabel("Трафик по процессам", self._proc_traffic_card))

        self._proc_traffic_table = TableWidget(self._proc_traffic_card)
        self._proc_traffic_table.setColumnCount(5)
        self._proc_traffic_table.setHorizontalHeaderLabels(
            ["Процесс", "\u2193 Загрузка", "\u2191 Выгрузка", "Соед.", "Маршрут"]
        )
        self._proc_traffic_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for col in range(1, 5):
            self._proc_traffic_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._proc_traffic_table.verticalHeader().setVisible(False)
        self._proc_traffic_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._proc_traffic_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )
        self._proc_traffic_table.setMinimumHeight(150)
        proc_layout.addWidget(self._proc_traffic_table, 1)
        self._proc_traffic_card.setVisible(False)

        # ── Routing card ──────────────────────────────────────
        self.routing_card = CardWidget(self)
        routing_layout = QVBoxLayout(self.routing_card)
        routing_layout.setContentsMargins(18, 16, 18, 16)
        routing_layout.setSpacing(8)
        routing_layout.addWidget(StrongBodyLabel("Маршрутизация", self.routing_card))
        self.mode_combo = ComboBox(self.routing_card)
        self.mode_combo.addItem("Глобальный", userData="global")
        self.mode_combo.addItem("Правила", userData="rule")
        self.mode_combo.addItem("Прямой", userData="direct")
        routing_layout.addWidget(self.mode_combo)
        self.routing_mode_label = BodyLabel("Правила", self.routing_card)
        self.routing_dns_label = CaptionLabel("DNS: Системный", self.routing_card)
        self.routing_rules_label = CaptionLabel("Прямые: 0   Прокси: 0   Блок: 0", self.routing_card)
        self.routing_bypass_label = CaptionLabel("Обход LAN: включён", self.routing_card)
        self.routing_bypass_label.setWordWrap(True)
        routing_layout.addWidget(self.routing_mode_label)
        routing_layout.addStretch(1)
        routing_layout.addWidget(self.routing_dns_label)
        routing_layout.addWidget(self.routing_rules_label)
        routing_layout.addWidget(self.routing_bypass_label)

        grid.addWidget(self.connection_card, 0, 0)
        grid.addWidget(self.profile_card, 0, 1)
        grid.addWidget(self.traffic_card, 1, 0)
        grid.addWidget(self.routing_card, 1, 1)
        grid.addWidget(self._proc_traffic_card, 2, 0, 1, 2)
        root.addLayout(grid)
        root.addStretch(1)

        # ── Page 1: traffic detail subpage ────────────────────
        self._traffic_detail_page = QWidget()
        self._traffic_detail_page.setStyleSheet("QWidget { background: transparent; }")
        self._stack.addWidget(self._traffic_detail_page)

        detail_layout = QVBoxLayout(self._traffic_detail_page)
        detail_layout.setContentsMargins(24, 20, 24, 20)
        detail_layout.setSpacing(12)

        self._traffic_breadcrumb = BreadcrumbBar(self._traffic_detail_page)
        self._traffic_breadcrumb.addItem("dashboard", "Панель управления")
        self._traffic_breadcrumb.addItem("traffic", "Трафик")
        self._traffic_breadcrumb.currentItemChanged.connect(self._on_traffic_breadcrumb)
        detail_layout.addWidget(self._traffic_breadcrumb)

        self._detail_graph = DetailTrafficGraphWidget(self._traffic_detail_page)
        detail_layout.addWidget(self._detail_graph, 1)

        detail_stats_row = QHBoxLayout()
        detail_stats_row.setSpacing(16)
        self._detail_down_label = BodyLabel("Загрузка: 0 B/s", self._traffic_detail_page)
        self._detail_up_label = BodyLabel("Выгрузка: 0 B/s", self._traffic_detail_page)
        self._detail_rtt_label = BodyLabel("RTT: --", self._traffic_detail_page)
        self._detail_peak_label = BodyLabel("Пик: 0 B/s", self._traffic_detail_page)
        detail_stats_row.addWidget(self._detail_down_label)
        detail_stats_row.addWidget(self._detail_up_label)
        detail_stats_row.addWidget(self._detail_rtt_label)
        detail_stats_row.addWidget(self._detail_peak_label)
        detail_stats_row.addStretch(1)
        detail_layout.addLayout(detail_stats_row)

        # ── Signal connections ────────────────────────────────
        self.node_combo.currentIndexChanged.connect(self._on_node_changed)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.tun_switch.checkedChanged.connect(self._on_tun_toggled)
        self.proxy_switch.checkedChanged.connect(self._on_proxy_toggled)
        self.toggle_btn.clicked.connect(self.toggle_connection_requested)

        self._stack.setCurrentIndex(0)
        self._refresh_dashboard()

    # ── Public API ────────────────────────────────────────────

    def set_nodes(self, nodes: list[Node], selected_node_id: str | None) -> None:
        self._nodes = list(nodes)
        self._node_ids = []

        self.node_combo.blockSignals(True)
        self.node_combo.clear()

        selected_index = 0
        for index, node in enumerate(self._nodes):
            self.node_combo.addItem(self._node_title(node))
            self._node_ids.append(node.id)
            if selected_node_id and selected_node_id == node.id:
                selected_index = index

        if self._nodes:
            self.node_combo.setEnabled(True)
            self.node_combo.setCurrentIndex(selected_index)
            self._selected_node = self._nodes[selected_index]
        else:
            self.node_combo.addItem("Профили не импортированы")
            self.node_combo.setEnabled(False)
            self._selected_node = None

        self.node_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_selected_node(self, node: Node | None) -> None:
        self._selected_node = node
        if node is not None and node.id in self._node_ids:
            self.node_combo.blockSignals(True)
            self.node_combo.setCurrentIndex(self._node_ids.index(node.id))
            self.node_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_connection(self, connected: bool) -> None:
        self._connected = connected
        if not connected:
            self._last_down_bps = 0.0
            self._last_up_bps = 0.0
            self._live_rtt_ms = None
            self._peak_bps = 0.0
            self._down_history.clear()
            self._up_history.clear()
            self.traffic_graph.clear_data()
        self._refresh_dashboard()

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self._routing.mode = mode
        self.mode_combo.blockSignals(True)
        for index in range(self.mode_combo.count()):
            if self.mode_combo.itemData(index) == mode:
                self.mode_combo.setCurrentIndex(index)
                break
        self.mode_combo.blockSignals(False)
        self._refresh_dashboard()

    def set_proxy_ports(self, socks_port: int, http_port: int) -> None:
        self._settings.socks_port = socks_port
        self._settings.http_port = http_port
        self._settings.tun_mode = False
        self._refresh_dashboard()

    def set_tun_mode(self, enabled: bool) -> None:
        self._settings.tun_mode = enabled
        self._refresh_dashboard()

    def set_settings_snapshot(self, settings: AppSettings) -> None:
        self._settings = settings
        self._sync_switches()
        self._refresh_dashboard()

    def set_routing_snapshot(self, routing: RoutingSettings) -> None:
        self._routing = routing
        self.set_mode(routing.mode)

    def set_selected_latency(self, value: int | None) -> None:
        self._selected_latency_ms = value
        if self._selected_node is not None:
            self._selected_node.ping_ms = value
        self._refresh_dashboard()

    def set_live_metrics(self, down_bps: float, up_bps: float, latency_ms: int | None) -> None:
        self._last_down_bps = max(0.0, down_bps)
        self._last_up_bps = max(0.0, up_bps)
        self._live_rtt_ms = latency_ms
        self._peak_bps = max(self._peak_bps, self._last_down_bps, self._last_up_bps)
        self._down_history.append(self._last_down_bps)
        self._up_history.append(self._last_up_bps)
        self.traffic_graph.add_point(self._last_down_bps, self._last_up_bps)
        if self._stack.currentIndex() == 1:
            self._detail_graph.add_point(self._last_down_bps, self._last_up_bps)
        self._refresh_dashboard()

    def set_process_stats(self, stats: list | None) -> None:
        if stats is None:
            return
        self._proc_traffic_card.setVisible(bool(stats))
        self._proc_traffic_table.setRowCount(len(stats))
        for row, ps in enumerate(stats):
            self._proc_traffic_table.setItem(row, 0, QTableWidgetItem(ps.exe))
            self._proc_traffic_table.setItem(
                row, 1, QTableWidgetItem(self._format_bytes(ps.download))
            )
            self._proc_traffic_table.setItem(
                row, 2, QTableWidgetItem(self._format_bytes(ps.upload))
            )
            self._proc_traffic_table.setItem(
                row, 3, QTableWidgetItem(str(ps.connections))
            )
            route_text = (
                "VPN"
                if ps.route == "proxy"
                else ("Прямой" if ps.route == "direct" else "Смешан.")
            )
            item = QTableWidgetItem(route_text)
            if ps.route == "proxy":
                item.setForeground(QColor("#2ecc71"))
            self._proc_traffic_table.setItem(row, 4, item)

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / 1024 / 1024:.1f} MB"
        else:
            return f"{b / 1024 / 1024 / 1024:.2f} GB"

    # ── Refresh logic ─────────────────────────────────────────

    def _refresh_dashboard(self) -> None:
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _do_refresh_dashboard(self) -> None:
        self._refresh_connection_card()
        self._refresh_profile_card()
        self._refresh_traffic_card()
        self._refresh_routing_card()
        has_profiles = bool(self._nodes)
        self.toggle_btn.setEnabled(has_profiles)
        if self._stack.currentIndex() == 1:
            self._refresh_detail_stats()

    def _refresh_connection_card(self) -> None:
        action = "VPN" if self._settings.tun_mode else "Прокси"
        self.connection_state_label.setText("Подключено" if self._connected else "Ожидание")
        self.connection_engine_label.setText(self._route_engine_label())
        self.connection_status_label.setText(f"{action} {'работает' if self._connected else 'остановлен'}")
        self.connection_target_label.setText(self._selected_node_summary())
        self.toggle_btn.setText(self._toggle_action_text())
        self.toggle_btn.setIcon(FIF.PAUSE_BOLD if self._connected else FIF.PLAY_SOLID)
        self.summary_label.setText(self._summary_text())

    def _refresh_profile_card(self) -> None:
        selected = self._selected_node
        if selected is None:
            self.profile_name_label.setText("Профиль не выбран")
            self.profile_endpoint_label.setText("Сначала импортируйте или выберите узел")
            self.profile_group_label.setText(f"Профилей: {len(self._nodes)}")
            self.profile_latency_label.setText("Задержка: --")
            return

        self.profile_name_label.setText(selected.name or "Безымянный профиль")
        scheme = selected.scheme.upper() if selected.scheme else "NODE"
        self.profile_endpoint_label.setText(f"{selected.server or '--'}:{selected.port or '--'}  ({scheme})")
        self.profile_group_label.setText(f"Группа: {selected.group or 'По умолчанию'}")
        self.profile_latency_label.setText(f"Задержка: {_format_latency(self._effective_latency())}")

    def _refresh_traffic_card(self) -> None:
        self.traffic_down_label.setText(f"Загрузка: {_format_speed(self._last_down_bps)}")
        self.traffic_up_label.setText(f"Выгрузка: {_format_speed(self._last_up_bps)}")
        self.traffic_rtt_label.setText(f"RTT: {_format_latency(self._effective_latency())}")
        self.traffic_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")

    def _refresh_routing_card(self) -> None:
        self.routing_mode_label.setText(_mode_title(self._routing.mode))
        self.routing_dns_label.setText(f"DNS: {self._routing.dns_mode.title()}")
        self.routing_rules_label.setText(
            f"Прямые: {len(self._routing.direct_domains)}   Прокси: {len(self._routing.proxy_domains)}   Блок: {len(self._routing.block_domains)}"
        )
        bypass = "включён" if self._routing.bypass_lan else "выключен"
        self.routing_bypass_label.setText(f"Обход LAN: {bypass}")

    def _refresh_detail_stats(self) -> None:
        self._detail_down_label.setText(f"Загрузка: {_format_speed(self._last_down_bps)}")
        self._detail_up_label.setText(f"Выгрузка: {_format_speed(self._last_up_bps)}")
        self._detail_rtt_label.setText(f"RTT: {_format_latency(self._effective_latency())}")
        self._detail_peak_label.setText(f"Пик: {_format_speed(self._peak_bps)}")

    # ── Traffic subpage navigation ────────────────────────────

    def _show_traffic_page(self) -> None:
        """Switch to the traffic detail subpage."""
        self._detail_graph.set_data(self._down_history, self._up_history)
        self._refresh_detail_stats()
        self._reset_traffic_breadcrumb()
        self._stack.setCurrentIndex(1)

    def _show_main_page(self) -> None:
        """Switch back to the main dashboard."""
        self._stack.setCurrentIndex(0)

    def _on_traffic_breadcrumb(self, routeKey: str) -> None:
        if routeKey == "dashboard":
            self._show_main_page()

    def _reset_traffic_breadcrumb(self) -> None:
        """Reset breadcrumb to initial two-item state."""
        self._traffic_breadcrumb.blockSignals(True)
        self._traffic_breadcrumb.clear()
        self._traffic_breadcrumb.addItem("dashboard", "Панель управления")
        self._traffic_breadcrumb.addItem("traffic", "Трафик")
        self._traffic_breadcrumb.blockSignals(False)

    # ── Helpers ───────────────────────────────────────────────

    def _effective_latency(self) -> int | None:
        return self._live_rtt_ms if self._live_rtt_ms is not None else self._selected_latency_ms

    def _route_engine_label(self) -> str:
        if self._settings.tun_mode:
            return "Режим VPN (TUN)"
        if self._settings.enable_system_proxy:
            return f"Системный прокси  HTTP {self._settings.http_port} / SOCKS {self._settings.socks_port}"
        return f"Локальный прокси  HTTP {self._settings.http_port} / SOCKS {self._settings.socks_port}"

    def _toggle_action_text(self) -> str:
        if self._settings.tun_mode:
            return "Остановить VPN" if self._connected else "Запустить VPN"
        return "Остановить прокси" if self._connected else "Запустить прокси"

    def _selected_node_summary(self) -> str:
        if self._selected_node is None:
            return "Активный профиль не выбран"
        group = self._selected_node.group or "По умолчанию"
        scheme = self._selected_node.scheme.upper() if self._selected_node.scheme else "NODE"
        server = self._selected_node.server or "unknown-host"
        port = self._selected_node.port or "--"
        return f"{group}  {scheme}  {server}:{port}"

    def _summary_text(self) -> str:
        if self._selected_node is None:
            return "Выберите узел, чтобы запустить прокси или VPN и просмотреть состояние сеанса."
        if self._connected:
            return f"Активный сеанс: {self._selected_node_summary()}"
        return f"Готов к запуску: {self._selected_node_summary()}"

    def _node_title(self, node: Node) -> str:
        name = node.name or node.server or "Безымянный"
        scheme = node.scheme.upper() if node.scheme else "NODE"
        return f"{name} ({scheme})"

    # ── Signal handlers ───────────────────────────────────────

    def _on_node_changed(self, index: int) -> None:
        if 0 <= index < len(self._node_ids):
            self.node_selected.emit(self._node_ids[index])

    def _on_mode_changed(self, index: int) -> None:
        value = self.mode_combo.itemData(index)
        if value:
            self.mode_changed.emit(str(value))

    def _on_tun_toggled(self, checked: bool) -> None:
        self.proxy_switch.setEnabled(not checked)
        self.tun_toggled.emit(checked)

    def _on_proxy_toggled(self, checked: bool) -> None:
        self.proxy_toggled.emit(checked)

    def _sync_switches(self) -> None:
        self.tun_switch.blockSignals(True)
        self.tun_switch.setChecked(self._settings.tun_mode)
        self.tun_switch.setText("Вкл" if self._settings.tun_mode else "Выкл")
        self.tun_switch.blockSignals(False)

        self.proxy_switch.blockSignals(True)
        self.proxy_switch.setChecked(self._settings.enable_system_proxy)
        self.proxy_switch.setText("Вкл" if self._settings.enable_system_proxy else "Выкл")
        self.proxy_switch.setEnabled(not self._settings.tun_mode)
        self.proxy_switch.blockSignals(False)
