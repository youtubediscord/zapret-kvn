from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
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
    PrimaryPushButton,
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
            "Работает только в режиме системного прокси (без TUN)", container
        )
        root.addWidget(self.process_info)

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

        self.tun_warning = CaptionLabel(
            "В режиме TUN маршрутизация по процессам недоступна", container
        )
        self.tun_warning.setStyleSheet("color: #e6a700;")
        self.tun_warning.setVisible(False)
        root.addWidget(self.tun_warning)

        # --- Apply button ---
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.apply_btn = PrimaryPushButton("Применить маршрутизацию", container)
        btn_row.addWidget(self.apply_btn)
        root.addLayout(btn_row)
        root.addStretch(1)

        # --- Signals ---
        self.apply_btn.clicked.connect(self._emit_apply)
        self.add_rule_btn.clicked.connect(lambda: self._add_rule_row())
        self.del_rule_btn.clicked.connect(self._del_selected_rules)
        self.import_btn.clicked.connect(self._import_rules)
        self.export_btn.clicked.connect(self._export_rules)
        self.add_proc_btn.clicked.connect(self._browse_exe)
        self.del_proc_btn.clicked.connect(self._del_selected_procs)

    # --- Public API ---

    def set_routing(self, routing: RoutingSettings) -> None:
        self._loading = True
        self._select_combo_value(self.mode_combo, routing.mode)
        self._select_combo_value(self.dns_combo, routing.dns_mode)
        self.bypass_switch.setChecked(routing.bypass_lan)

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

    def set_tun_mode(self, enabled: bool) -> None:
        self._process_container.setEnabled(not enabled)
        self.add_proc_btn.setEnabled(not enabled)
        self.del_proc_btn.setEnabled(not enabled)
        self.tun_warning.setVisible(enabled)

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
        self.rules_table.setCellWidget(row, 1, combo)

    def _del_selected_rules(self) -> None:
        rows = sorted({idx.row() for idx in self.rules_table.selectedIndexes()}, reverse=True)
        for r in rows:
            self.rules_table.removeRow(r)

    def _import_rules(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Импорт правил", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except Exception:
            return
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
        self.proc_table.setCellWidget(row, 1, combo)

    def _browse_exe(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать приложение", "", "Executables (*.exe)"
        )
        if not path:
            return
        name = os.path.basename(path)
        for row in range(self.proc_table.rowCount()):
            item = self.proc_table.item(row, 0)
            if item and item.text().lower() == name.lower():
                return
        self._add_process_row(name, "proxy")

    def _del_selected_procs(self) -> None:
        rows = sorted({idx.row() for idx in self.proc_table.selectedIndexes()}, reverse=True)
        for r in rows:
            self.proc_table.removeRow(r)

    # --- Emit ---

    def _emit_apply(self) -> None:
        mode = self.mode_combo.currentData() or "rule"
        dns_mode = self.dns_combo.currentData() or "system"

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

        routing = RoutingSettings(
            mode=str(mode),
            bypass_lan=self.bypass_switch.isChecked(),
            direct_domains=direct,
            proxy_domains=proxy,
            block_domains=block,
            dns_mode=str(dns_mode),
            process_rules=process_rules,
            service_routes=service_routes,
        )
        self.apply_requested.emit(routing)

    # --- Helpers ---

    @staticmethod
    def _select_combo_value(combo: ComboBox, value: str) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return
