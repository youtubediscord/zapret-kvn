from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FluentIcon as FIF,
    PrimaryToolButton,
    SettingCard,
    SettingCardGroup,
    SmoothScrollArea,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TransparentToolButton,
)

from ..models import RoutingSettings
from ..process_presets import PROCESS_PRESETS
from ..service_presets import SERVICE_PRESETS

_ACTIONS = [
    ("Прямой", "direct"),
    ("Прокси", "proxy"),
    ("Блокировка", "block"),
]
_ACTION_LABELS = {data: label for label, data in _ACTIONS}
_ACTION_DATA = {label: data for label, data in _ACTIONS}

_SERVICE_ACTIONS = [
    ("Прокси", "proxy"),
    ("Прямой", "direct"),
    ("Блокировка", "block"),
]


class _ServiceRouteCard(SettingCard):
    """Setting card with action combo + switch for service routing."""

    changed = pyqtSignal()

    def __init__(self, icon, title, content, parent=None):
        super().__init__(icon, title, content, parent)
        self.action_combo = ComboBox(self)
        for label, data in _SERVICE_ACTIONS:
            self.action_combo.addItem(label, userData=data)
        self.action_combo.setMinimumWidth(120)

        self.switch = SwitchButton(self)
        self.switch.setOnText("Вкл")
        self.switch.setOffText("Выкл")

        self.hBoxLayout.addWidget(self.action_combo, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(12)
        self.hBoxLayout.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignRight)
        self.hBoxLayout.addSpacing(16)

        self.switch.checkedChanged.connect(self._on_changed)
        self.action_combo.currentIndexChanged.connect(self._on_changed)

    def _on_changed(self):
        self.action_combo.setEnabled(self.switch.isChecked())
        self.changed.emit()

    def set_state(self, enabled: bool, action: str = "proxy"):
        self.switch.setChecked(enabled)
        for i in range(self.action_combo.count()):
            if self.action_combo.itemData(i) == action:
                self.action_combo.setCurrentIndex(i)
                break
        self.action_combo.setEnabled(enabled)

    def get_state(self) -> tuple[bool, str]:
        return self.switch.isChecked(), self.action_combo.currentData() or "proxy"


class RoutingPage(QWidget):
    apply_requested = pyqtSignal(object)  # emits RoutingSettings

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("routing")
        self._loading = False

        # Debounce timer for auto-apply
        self._apply_timer = QTimer(self)
        self._apply_timer.setSingleShot(True)
        self._apply_timer.setInterval(300)
        self._apply_timer.timeout.connect(self._emit_apply)

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
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Маршрутизация", container))

        # --- Header: mode, DNS, bypass LAN ---
        header = QGridLayout()
        header.setHorizontalSpacing(12)
        header.setVerticalSpacing(8)

        header.addWidget(BodyLabel("Режим", container), 0, 0)
        self.mode_combo = ComboBox(container)
        self.mode_combo.addItem("Глобальный", userData="global")
        self.mode_combo.addItem("По правилам", userData="rule")
        self.mode_combo.addItem("Прямой", userData="direct")
        header.addWidget(self.mode_combo, 0, 1)

        header.addWidget(BodyLabel("DNS", container), 1, 0)
        self.dns_combo = ComboBox(container)
        self.dns_combo.addItem("Системный DNS", userData="system")
        self.dns_combo.addItem("Встроенный DNS", userData="builtin")
        header.addWidget(self.dns_combo, 1, 1)

        self.bypass_switch = SwitchButton("Обход локальной сети", container)
        header.addWidget(self.bypass_switch, 2, 0, 1, 2)

        # --- TUN DNS settings (visible only in TUN mode) ---
        self._dns_tun_widget = QWidget(container)
        dns_grid = QGridLayout(self._dns_tun_widget)
        dns_grid.setContentsMargins(0, 4, 0, 0)
        dns_grid.setHorizontalSpacing(8)
        dns_grid.setVerticalSpacing(6)

        dns_grid.addWidget(CaptionLabel("Bootstrap DNS (direct):", container), 0, 0)
        self._dns_bootstrap_server = ComboBox(container)
        for label, ip in [("Cloudflare 1.1.1.1", "1.1.1.1"), ("Google 8.8.8.8", "8.8.8.8"),
                          ("Quad9 9.9.9.9", "9.9.9.9"), ("Яндекс 77.88.8.8", "77.88.8.8"),
                          ("OpenDNS 208.67.222.222", "208.67.222.222")]:
            self._dns_bootstrap_server.addItem(label, userData=ip)
        self._dns_bootstrap_server.setMinimumWidth(180)
        dns_grid.addWidget(self._dns_bootstrap_server, 0, 1)

        self._dns_bootstrap_type = ComboBox(container)
        for label, val in [("UDP", "udp"), ("TCP", "tcp"), ("DoT (TLS)", "tls"), ("DoH (HTTPS)", "https")]:
            self._dns_bootstrap_type.addItem(label, userData=val)
        dns_grid.addWidget(self._dns_bootstrap_type, 0, 2)

        dns_grid.addWidget(CaptionLabel("Proxy DNS (VPN):", container), 1, 0)
        self._dns_proxy_server = ComboBox(container)
        for label, ip in [("Google 8.8.8.8", "8.8.8.8"), ("Cloudflare 1.1.1.1", "1.1.1.1"),
                          ("Quad9 9.9.9.9", "9.9.9.9"), ("OpenDNS 208.67.222.222", "208.67.222.222")]:
            self._dns_proxy_server.addItem(label, userData=ip)
        self._dns_proxy_server.setMinimumWidth(180)
        dns_grid.addWidget(self._dns_proxy_server, 1, 1)

        self._dns_proxy_type = ComboBox(container)
        for label, val in [("TCP", "tcp"), ("DoT (TLS)", "tls"), ("DoH (HTTPS)", "https")]:
            self._dns_proxy_type.addItem(label, userData=val)
        dns_grid.addWidget(self._dns_proxy_type, 1, 2)

        self._dns_tun_widget.setVisible(False)
        header.addWidget(self._dns_tun_widget, 3, 0, 1, 2)

        root.addLayout(header)

        # --- Services section ---
        self._services_group = SettingCardGroup("Сервисы", container)
        self._service_cards: dict[str, _ServiceRouteCard] = {}

        for preset in SERVICE_PRESETS:
            card = _ServiceRouteCard(
                preset.icon,
                preset.name,
                preset.description,
                parent=self._services_group,
            )
            card.changed.connect(self._schedule_apply)
            self._services_group.addSettingCard(card)
            self._service_cards[preset.id] = card

        root.addWidget(self._services_group)

        # --- Rules table ---
        root.addWidget(SubtitleLabel("Правила маршрутизации", container))

        rules_toolbar = QHBoxLayout()
        self.add_rule_btn = PrimaryToolButton(FIF.ADD, container)
        self.add_rule_btn.setToolTip("Добавить правило")
        rules_toolbar.addWidget(self.add_rule_btn)

        self.del_rule_btn = TransparentToolButton(FIF.DELETE, container)
        self.del_rule_btn.setToolTip("Удалить выбранные")
        rules_toolbar.addWidget(self.del_rule_btn)

        rules_toolbar.addSpacing(16)

        self.import_btn = TransparentToolButton(FIF.DOWNLOAD, container)
        self.import_btn.setToolTip("Импорт из файла")
        rules_toolbar.addWidget(self.import_btn)

        self.export_btn = TransparentToolButton(FIF.SHARE, container)
        self.export_btn.setToolTip("Экспорт в файл")
        rules_toolbar.addWidget(self.export_btn)

        rules_toolbar.addStretch(1)
        root.addLayout(rules_toolbar)

        self.rules_table = TableWidget(container)
        self.rules_table.setColumnCount(2)
        self.rules_table.setHorizontalHeaderLabels(["Адрес", "Действие"])
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setMinimumHeight(180)
        root.addWidget(self.rules_table)

        # --- Process routing section ---
        root.addWidget(SubtitleLabel("Маршрутизация по процессам", container))

        self.process_info = CaptionLabel(
            "В режиме TUN перехватывает весь трафик процесса. В системном прокси — только если приложение использует прокси.", container
        )
        root.addWidget(self.process_info)

        # TUN default outbound selector
        tun_default_row = QHBoxLayout()
        self._tun_default_label = BodyLabel("По умолчанию (TUN):", container)
        tun_default_row.addWidget(self._tun_default_label)
        self.tun_default_combo = ComboBox(container)
        self.tun_default_combo.addItem("Через прокси", userData="proxy")
        self.tun_default_combo.addItem("Напрямую", userData="direct")
        self.tun_default_combo.setMinimumWidth(160)
        tun_default_row.addWidget(self.tun_default_combo)
        tun_default_row.addStretch(1)
        self._tun_default_row_widget = QWidget(container)
        self._tun_default_row_widget.setLayout(tun_default_row)
        root.addWidget(self._tun_default_row_widget)

        self.tun_default_info = CaptionLabel(
            "Что делать с трафиком процессов, не указанных в таблице ниже. "
            "«Через прокси» — весь трафик через VPN, исключения идут напрямую. "
            "«Напрямую» — только указанные процессы идут через VPN.",
            container,
        )
        root.addWidget(self.tun_default_info)

        # Hidden by default — shown only in TUN mode
        self._tun_default_row_widget.setVisible(False)
        self.tun_default_info.setVisible(False)

        # --- Process presets (quick-add app groups) ---
        self._process_presets_group = SettingCardGroup("Быстрый выбор приложений", container)
        self._process_preset_cards: dict[str, _ServiceRouteCard] = {}
        for preset in PROCESS_PRESETS:
            card = _ServiceRouteCard(
                preset.icon,
                preset.name,
                preset.description,
                parent=self._process_presets_group,
            )
            card.changed.connect(self._schedule_apply)
            self._process_presets_group.addSettingCard(card)
            self._process_preset_cards[preset.id] = card
        root.addWidget(self._process_presets_group)
        self._process_presets_group.setVisible(False)  # shown only in TUN mode

        self._process_container = QWidget(container)
        proc_layout = QVBoxLayout(self._process_container)
        proc_layout.setContentsMargins(0, 0, 0, 0)
        proc_layout.setSpacing(8)

        proc_toolbar = QHBoxLayout()
        self.add_proc_btn = PrimaryToolButton(FIF.FOLDER_ADD, container)
        self.add_proc_btn.setToolTip("Добавить .exe")
        proc_toolbar.addWidget(self.add_proc_btn)

        self.del_proc_btn = TransparentToolButton(FIF.DELETE, container)
        self.del_proc_btn.setToolTip("Удалить выбранные")
        proc_toolbar.addWidget(self.del_proc_btn)

        proc_toolbar.addStretch(1)
        proc_layout.addLayout(proc_toolbar)

        self.proc_table = TableWidget(self._process_container)
        self.proc_table.setColumnCount(2)
        self.proc_table.setHorizontalHeaderLabels(["Процесс", "Действие"])
        self.proc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.proc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.proc_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.proc_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.setMinimumHeight(120)
        proc_layout.addWidget(self.proc_table)

        root.addWidget(self._process_container)

        self.proxy_warning = CaptionLabel(
            "В системном прокси: правила действуют только для приложений, использующих прокси", container
        )
        self.proxy_warning.setStyleSheet("color: #e6a700;")
        self.proxy_warning.setVisible(False)
        root.addWidget(self.proxy_warning)

        root.addStretch(1)

        # --- Signals ---
        self.mode_combo.currentIndexChanged.connect(self._schedule_apply)
        self.dns_combo.currentIndexChanged.connect(self._schedule_apply)
        self._dns_bootstrap_server.currentIndexChanged.connect(self._schedule_apply)
        self._dns_bootstrap_type.currentIndexChanged.connect(self._schedule_apply)
        self._dns_proxy_server.currentIndexChanged.connect(self._schedule_apply)
        self._dns_proxy_type.currentIndexChanged.connect(self._schedule_apply)
        self.bypass_switch.checkedChanged.connect(self._schedule_apply)
        self.tun_default_combo.currentIndexChanged.connect(self._schedule_apply)
        self.add_rule_btn.clicked.connect(self._on_add_rule)
        self.del_rule_btn.clicked.connect(self._on_del_rules)
        self.import_btn.clicked.connect(self._on_import_rules)
        self.export_btn.clicked.connect(self._export_rules)
        self.add_proc_btn.clicked.connect(self._on_browse_exe)
        self.del_proc_btn.clicked.connect(self._on_del_procs)
        self.rules_table.cellChanged.connect(self._schedule_apply)

    # --- Auto-apply ---

    def _schedule_apply(self) -> None:
        if not self._loading:
            self._apply_timer.start()

    # --- Public API ---

    def set_routing(self, routing: RoutingSettings) -> None:
        self._loading = True
        self._select_combo_value(self.mode_combo, routing.mode)
        self._select_combo_value(self.dns_combo, routing.dns_mode)
        self._select_combo_value(self._dns_bootstrap_server, routing.dns_bootstrap_server)
        self._select_combo_value(self._dns_bootstrap_type, routing.dns_bootstrap_type)
        self._select_combo_value(self._dns_proxy_server, routing.dns_proxy_server)
        self._select_combo_value(self._dns_proxy_type, routing.dns_proxy_type)
        self.bypass_switch.setChecked(routing.bypass_lan)
        self._select_combo_value(self.tun_default_combo, routing.tun_default_outbound)

        # Populate service cards
        use_defaults = not routing.service_routes
        for svc_id, card in self._service_cards.items():
            if use_defaults:
                preset = next((p for p in SERVICE_PRESETS if p.id == svc_id), None)
                if preset:
                    card.set_state(True, preset.default_action)
                else:
                    card.set_state(False, "proxy")
            elif svc_id in routing.service_routes:
                card.set_state(True, routing.service_routes[svc_id])
            else:
                card.set_state(False, "proxy")

        # Populate process preset cards
        use_proc_defaults = not routing.process_preset_routes
        for preset_id, card in self._process_preset_cards.items():
            if use_proc_defaults:
                preset = next((p for p in PROCESS_PRESETS if p.id == preset_id), None)
                if preset:
                    card.set_state(True, preset.default_action)
                else:
                    card.set_state(False, "proxy")
            elif preset_id in routing.process_preset_routes:
                card.set_state(True, routing.process_preset_routes[preset_id])
            else:
                card.set_state(False, "proxy")

        rows: list[tuple[str, str]] = []
        for addr in routing.direct_domains:
            rows.append((addr, "direct"))
        for addr in routing.proxy_domains:
            rows.append((addr, "proxy"))
        for addr in routing.block_domains:
            rows.append((addr, "block"))
        rows.sort(key=lambda r: r[0].lower())

        self.rules_table.setUpdatesEnabled(False)
        self.rules_table.setRowCount(0)
        for addr, action in rows:
            self._add_rule_row(addr, action)
        self.rules_table.setUpdatesEnabled(True)

        self.proc_table.setUpdatesEnabled(False)
        self.proc_table.setRowCount(0)
        for pr in routing.process_rules:
            name = pr.get("process", "")
            action = pr.get("action", "proxy")
            if name:
                self._add_process_row(name, action)
        self.proc_table.setUpdatesEnabled(True)

        self._loading = False

        # First launch: save defaults immediately
        if use_defaults:
            self._emit_apply()

    def set_tun_mode(self, enabled: bool) -> None:
        # Process routing works in both modes — show warning only in system proxy mode
        self._process_container.setEnabled(True)
        self.add_proc_btn.setEnabled(True)
        self.del_proc_btn.setEnabled(True)
        self.proxy_warning.setVisible(not enabled)
        # TUN default outbound + process presets + DNS settings only relevant in TUN mode
        self._tun_default_row_widget.setVisible(enabled)
        self._dns_tun_widget.setVisible(enabled)
        self.tun_default_info.setVisible(enabled)
        self._process_presets_group.setVisible(enabled)

    # --- Rules table helpers ---

    def _add_rule_row(self, addr: str = "", action: str = "proxy") -> None:
        row = self.rules_table.rowCount()
        self.rules_table.insertRow(row)

        addr_item = QTableWidgetItem(addr)
        addr_item.setFlags(addr_item.flags() | Qt.ItemFlag.ItemIsEditable)
        self.rules_table.setItem(row, 0, addr_item)

        combo = ComboBox()
        for label, data in _ACTIONS:
            combo.addItem(label, userData=data)
        self._select_combo_value(combo, action)
        combo.currentIndexChanged.connect(self._schedule_apply)
        self.rules_table.setCellWidget(row, 1, combo)

    def _on_add_rule(self) -> None:
        self._add_rule_row()

    def _on_del_rules(self) -> None:
        rows = sorted({idx.row() for idx in self.rules_table.selectedIndexes()}, reverse=True)
        for r in rows:
            self.rules_table.removeRow(r)
        if rows:
            self._schedule_apply()

    def _on_import_rules(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Импорт правил", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except Exception:
            return
        added = False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" in line:
                addr, action = line.rsplit("|", 1)
                action = action.strip().lower()
                if action not in ("direct", "proxy", "block"):
                    action = "proxy"
            else:
                addr = line
                action = "proxy"
            self._add_rule_row(addr.strip(), action)
            added = True
        if added:
            self._schedule_apply()

    def _export_rules(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт правил", "rules.txt", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        lines: list[str] = []
        for row in range(self.rules_table.rowCount()):
            item = self.rules_table.item(row, 0)
            combo = self.rules_table.cellWidget(row, 1)
            if item and combo:
                addr = item.text().strip()
                action = combo.currentData() or "proxy"
                if addr:
                    lines.append(f"{addr}|{action}")
        Path(path).write_text("\n".join(lines), encoding="utf-8")

    # --- Process table helpers ---

    def _add_process_row(self, name: str = "", action: str = "proxy") -> None:
        row = self.proc_table.rowCount()
        self.proc_table.insertRow(row)

        name_item = QTableWidgetItem(name)
        name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.proc_table.setItem(row, 0, name_item)

        combo = ComboBox()
        for label, data in _ACTIONS:
            combo.addItem(label, userData=data)
        self._select_combo_value(combo, action)
        combo.currentIndexChanged.connect(self._schedule_apply)
        self.proc_table.setCellWidget(row, 1, combo)

    _PROTECTED_PROCESSES = {"xray.exe", "sing-box.exe", "tun2socks.exe"}

    def _on_browse_exe(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать приложение", "", "Executables (*.exe)"
        )
        if not path:
            return
        name = os.path.basename(path)
        if name.lower() in self._PROTECTED_PROCESSES:
            from qfluentwidgets import InfoBar, InfoBarPosition
            InfoBar.warning(
                title="Защищённый процесс",
                content=f"{name} всегда использует прямое подключение для предотвращения петли маршрутизации",
                parent=self,
                duration=4000,
                position=InfoBarPosition.TOP,
            )
            return
        for row in range(self.proc_table.rowCount()):
            item = self.proc_table.item(row, 0)
            if item and item.text().lower() == name.lower():
                return
        self._add_process_row(name, "proxy")
        self._schedule_apply()

    def _on_del_procs(self) -> None:
        rows = sorted({idx.row() for idx in self.proc_table.selectedIndexes()}, reverse=True)
        for r in rows:
            self.proc_table.removeRow(r)
        if rows:
            self._schedule_apply()

    # --- Emit ---

    def _emit_apply(self) -> None:
        mode = self.mode_combo.currentData() or "rule"
        dns_mode = self.dns_combo.currentData() or "system"
        dns_bootstrap_server = self._dns_bootstrap_server.currentData() or "1.1.1.1"
        dns_bootstrap_type = self._dns_bootstrap_type.currentData() or "udp"
        dns_proxy_server = self._dns_proxy_server.currentData() or "8.8.8.8"
        dns_proxy_type = self._dns_proxy_type.currentData() or "tcp"

        direct: list[str] = []
        proxy: list[str] = []
        block: list[str] = []

        for row in range(self.rules_table.rowCount()):
            item = self.rules_table.item(row, 0)
            combo = self.rules_table.cellWidget(row, 1)
            if not item or not combo:
                continue
            addr = item.text().strip()
            if not addr:
                continue
            action = combo.currentData() or "proxy"
            if action == "direct":
                direct.append(addr)
            elif action == "block":
                block.append(addr)
            else:
                proxy.append(addr)

        process_rules: list[dict[str, str]] = []
        for row in range(self.proc_table.rowCount()):
            item = self.proc_table.item(row, 0)
            combo = self.proc_table.cellWidget(row, 1)
            if not item or not combo:
                continue
            name = item.text().strip()
            if not name:
                continue
            action = combo.currentData() or "proxy"
            process_rules.append({"process": name, "action": action})

        # Collect service states
        service_routes: dict[str, str] = {}
        for svc_id, card in self._service_cards.items():
            enabled, action = card.get_state()
            if enabled:
                service_routes[svc_id] = action

        # Collect process preset states
        process_preset_routes: dict[str, str] = {}
        for preset_id, card in self._process_preset_cards.items():
            enabled, action = card.get_state()
            if enabled:
                process_preset_routes[preset_id] = action

        tun_default_outbound = self.tun_default_combo.currentData() or "direct"

        routing = RoutingSettings(
            mode=str(mode),
            bypass_lan=self.bypass_switch.isChecked(),
            direct_domains=direct,
            proxy_domains=proxy,
            block_domains=block,
            dns_mode=str(dns_mode),
            dns_bootstrap_server=str(dns_bootstrap_server),
            dns_bootstrap_type=str(dns_bootstrap_type),
            dns_proxy_server=str(dns_proxy_server),
            dns_proxy_type=str(dns_proxy_type),
            process_rules=process_rules,
            process_preset_routes=process_preset_routes,
            service_routes=service_routes,
            tun_default_outbound=str(tun_default_outbound),
        )
        self.apply_requested.emit(routing)

    # --- Helpers ---

    @staticmethod
    def _select_combo_value(combo: ComboBox, value: str) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return
