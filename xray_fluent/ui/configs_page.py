from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QStackedWidget, QVBoxLayout, QWidget
from qfluentwidgets import (
    BodyLabel,
    CaptionLabel,
    ComboBox,
    MessageBox,
    PlainTextEdit,
    PrimaryPushButton,
    PushButton,
    SegmentedWidget,
    SubtitleLabel,
)


class _RawConfigEditor(QWidget):
    open_requested = pyqtSignal()
    reset_requested = pyqtSignal()
    save_requested = pyqtSignal(str)
    validate_requested = pyqtSignal(str)
    apply_requested = pyqtSignal(str)
    config_selected = pyqtSignal(str)
    template_selected = pyqtSignal(str)

    def __init__(
        self,
        title: str,
        *,
        hint_text: str,
        detail_hint_text: str = "",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._title = title
        self._current_path = ""
        self._saved_text = ""
        self._selector_updating = False
        self._selected_config_key = ""
        self._selected_template_key = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        selectors = QHBoxLayout()
        selectors.setSpacing(8)
        selectors.addWidget(BodyLabel("Конфиг", self))
        self.config_combo = ComboBox(self)
        self.config_combo.setMinimumWidth(280)
        selectors.addWidget(self.config_combo, 1)
        selectors.addSpacing(12)
        selectors.addWidget(BodyLabel("Шаблон", self))
        self.template_combo = ComboBox(self)
        self.template_combo.setMinimumWidth(280)
        selectors.addWidget(self.template_combo, 1)
        root.addLayout(selectors)

        self.file_label = CaptionLabel("Файл: --", self)
        self.file_label.setWordWrap(True)
        root.addWidget(self.file_label)

        self.template_label = CaptionLabel("Шаблон: --", self)
        self.template_label.setWordWrap(True)
        root.addWidget(self.template_label)

        self.hint_label = CaptionLabel(hint_text, self)
        self.hint_label.setWordWrap(True)
        root.addWidget(self.hint_label)

        self.detail_hint_label = CaptionLabel(detail_hint_text, self)
        self.detail_hint_label.setWordWrap(True)
        self.detail_hint_label.setVisible(bool(detail_hint_text.strip()))
        root.addWidget(self.detail_hint_label)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.open_btn = PushButton("Импорт шаблона", self)
        self.reset_btn = PushButton("Сбросить к шаблону", self)
        self.save_btn = PushButton("Сохранить", self)
        self.validate_btn = PushButton("Проверить JSON", self)
        self.apply_btn = PrimaryPushButton("Применить", self)
        toolbar.addWidget(self.open_btn)
        toolbar.addWidget(self.reset_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.validate_btn)
        toolbar.addStretch(1)
        toolbar.addWidget(self.apply_btn)
        root.addLayout(toolbar)

        self.editor = PlainTextEdit(self)
        self.editor.setPlaceholderText(f"Raw {title}.json")
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)
        root.addWidget(self.editor, 1)

        root.addWidget(BodyLabel("Статус", self))
        self.status_box = PlainTextEdit(self)
        self.status_box.setReadOnly(True)
        self.status_box.setFixedHeight(92)
        self.status_box.setFont(font)
        root.addWidget(self.status_box)

        self.editor.textChanged.connect(self._on_text_changed)
        self.open_btn.clicked.connect(self._on_open_clicked)
        self.reset_btn.clicked.connect(self._on_reset_clicked)
        self.save_btn.clicked.connect(lambda: self.save_requested.emit(self.editor.toPlainText()))
        self.validate_btn.clicked.connect(lambda: self.validate_requested.emit(self.editor.toPlainText()))
        self.apply_btn.clicked.connect(lambda: self.apply_requested.emit(self.editor.toPlainText()))
        self.config_combo.currentIndexChanged.connect(lambda _index: self._on_config_combo_changed())
        self.template_combo.currentIndexChanged.connect(lambda _index: self._on_template_combo_changed())

        self.set_template_source(None)
        self._refresh_file_label()

    def set_document(self, path: Path, text: str) -> None:
        self._current_path = str(path)
        self.editor.blockSignals(True)
        self.editor.setPlainText(text)
        self.editor.blockSignals(False)
        self._saved_text = text
        self._refresh_file_label()

    def set_status(self, level: str, message: str) -> None:
        prefix = {
            "success": "OK",
            "warning": "Внимание",
            "error": "Ошибка",
            "info": "Инфо",
        }.get(level.strip().lower(), "Статус")
        self.status_box.setPlainText(f"{prefix}: {message}".strip())

    def set_template_source(self, path: Path | None) -> None:
        if path is None:
            self.template_label.setText("Шаблон: --")
            self.reset_btn.setEnabled(False)
            return
        self.template_label.setText(f"Шаблон: {path.as_posix()}")
        self.reset_btn.setEnabled(True)

    def set_available_configs(self, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._set_combo_items(self.config_combo, items, selected or "", placeholder="Нет конфигов")
        self._selected_config_key = self._current_combo_value(self.config_combo)

    def set_available_templates(self, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._set_combo_items(
            self.template_combo,
            items,
            selected or "",
            placeholder="Нет шаблонов",
            empty_label="Шаблон не выбран",
        )
        self._selected_template_key = self._current_combo_value(self.template_combo)

    def mark_saved(self, path: Path | None = None, text: str | None = None) -> None:
        if path is not None:
            self._current_path = str(path)
        if text is None:
            text = self.editor.toPlainText()
        self._saved_text = text
        self._refresh_file_label()

    def is_dirty(self) -> bool:
        return self.editor.toPlainText() != self._saved_text

    def _set_combo_items(
        self,
        combo: ComboBox,
        items: list[tuple[str, str]],
        selected: str,
        *,
        placeholder: str,
        empty_label: str = "",
    ) -> None:
        self._selector_updating = True
        try:
            combo.clear()
            if not items:
                combo.addItem(placeholder, userData="")
                combo.setEnabled(False)
                combo.setCurrentIndex(0)
                return
            combo.setEnabled(True)
            if empty_label:
                combo.addItem(empty_label, userData="")
            for label, data in items:
                combo.addItem(label, userData=data)
            match_index = 0
            for index in range(combo.count()):
                if combo.itemData(index) == selected:
                    match_index = index
                    break
            combo.setCurrentIndex(match_index)
        finally:
            self._selector_updating = False

    @staticmethod
    def _current_combo_value(combo: ComboBox) -> str:
        value = combo.currentData()
        return str(value or "").strip()

    def _restore_combo_selection(self, combo: ComboBox, value: str) -> None:
        self._selector_updating = True
        try:
            for index in range(combo.count()):
                if str(combo.itemData(index) or "").strip() == value:
                    combo.setCurrentIndex(index)
                    return
            if combo.count() > 0:
                combo.setCurrentIndex(0)
        finally:
            self._selector_updating = False

    def _confirm_discard_for_switch(self, title: str, text: str, confirm_text: str) -> bool:
        if not self.is_dirty():
            return True
        box = MessageBox(title, text, self.window())
        box.yesButton.setText(confirm_text)
        box.cancelButton.setText("Отмена")
        return bool(box.exec())

    def _on_config_combo_changed(self) -> None:
        if self._selector_updating:
            return
        value = self._current_combo_value(self.config_combo)
        if not value or value == self._selected_config_key:
            return
        if not self._confirm_discard_for_switch(
            "Несохранённые изменения",
            "Открыть другой конфиг без сохранения текущих правок?",
            "Открыть",
        ):
            self._restore_combo_selection(self.config_combo, self._selected_config_key)
            return
        self._selected_config_key = value
        self.config_selected.emit(value)

    def _on_template_combo_changed(self) -> None:
        if self._selector_updating:
            return
        value = self._current_combo_value(self.template_combo)
        if not value or value == self._selected_template_key:
            return
        if not self._confirm_discard_for_switch(
            "Несохранённые изменения",
            "Применить другой шаблон без сохранения текущих правок?",
            "Применить",
        ):
            self._restore_combo_selection(self.template_combo, self._selected_template_key)
            return
        self._selected_template_key = value
        self.template_selected.emit(value)

    def _on_open_clicked(self) -> None:
        if self.is_dirty():
            box = MessageBox(
                "Несохранённые изменения",
                "Импортировать другой шаблон без сохранения текущих правок?",
                self.window(),
            )
            box.yesButton.setText("Импортировать")
            box.cancelButton.setText("Отмена")
            if not box.exec():
                return
        self.open_requested.emit()

    def _on_reset_clicked(self) -> None:
        if self.is_dirty():
            box = MessageBox(
                "Несохранённые изменения",
                "Сбросить активную копию к шаблону и потерять текущие несохранённые правки?",
                self.window(),
            )
            box.yesButton.setText("Сбросить")
            box.cancelButton.setText("Отмена")
            if not box.exec():
                return
        self.reset_requested.emit()

    def _on_text_changed(self) -> None:
        self._refresh_file_label()

    def _refresh_file_label(self) -> None:
        label = Path(self._current_path).as_posix() if self._current_path else "--"
        suffix = " *" if self.is_dirty() else ""
        self.file_label.setText(f"Файл: {label}{suffix}")


class ConfigsPage(QWidget):
    open_requested = pyqtSignal(str)
    reset_requested = pyqtSignal(str)
    save_requested = pyqtSignal(str, str)
    validate_requested = pyqtSignal(str, str)
    apply_requested = pyqtSignal(str, str)
    config_selected = pyqtSignal(str, str)
    template_selected = pyqtSignal(str, str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("configs")

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        root.addWidget(SubtitleLabel("Конфиги", self))

        self.segmented = SegmentedWidget(self)
        root.addWidget(self.segmented)
        self.segmented.currentItemChanged.connect(self._on_current_core_changed)

        self.stack = QStackedWidget(self)
        root.addWidget(self.stack, 1)

        self._editors = {
            "singbox": _RawConfigEditor(
                "sing-box",
                hint_text="Если в конфиге есть outbound tag `proxy`, он будет заменён на выбранный сервер перед запуском.",
                detail_hint_text=(
                    "В режиме sing-box TUN правила процесса и пути применяются к перехваченному системному трафику. "
                    "Если выбранный сервер нельзя запустить нативным sing-box outbound, приложение автоматически "
                    "оставит этот же raw sing-box.json базой и поднимет local xray sidecar только для proxy path."
                ),
                parent=self,
            ),
            "xray": _RawConfigEditor(
                "xray",
                hint_text="Если в конфиге есть outbound tag `proxy`, он будет заменён на выбранный сервер перед запуском.",
                detail_hint_text=(
                    "Direct xray mode использует тот же raw xray.json только для трафика, который уже вошёл в xray "
                    "через системный прокси Windows или ручную proxy-настройку приложения. "
                    "xray TUN mode использует этот же raw xray.json как true TUN path, поэтому process/path rules "
                    "из xray routing начинают работать на системный трафик."
                ),
                parent=self,
            ),
        }
        self._labels = {
            "singbox": "sing-box",
            "xray": "xray",
        }
        self._indexes: dict[str, int] = {}

        for index, core in enumerate(("singbox", "xray")):
            editor = self._editors[core]
            self._indexes[core] = index
            self.stack.addWidget(editor)
            self.segmented.addItem(core, self._labels[core])
            editor.open_requested.connect(lambda key=core: self.open_requested.emit(key))
            editor.reset_requested.connect(lambda key=core: self.reset_requested.emit(key))
            editor.save_requested.connect(lambda text, key=core: self.save_requested.emit(key, text))
            editor.validate_requested.connect(lambda text, key=core: self.validate_requested.emit(key, text))
            editor.apply_requested.connect(lambda text, key=core: self.apply_requested.emit(key, text))
            editor.config_selected.connect(lambda value, key=core: self.config_selected.emit(key, value))
            editor.template_selected.connect(lambda value, key=core: self.template_selected.emit(key, value))

        self.set_current_core("singbox")

    def set_current_core(self, core: str) -> None:
        if core not in self._editors:
            return
        if self.segmented.currentRouteKey() != core:
            self.segmented.setCurrentItem(core)
        self.stack.setCurrentIndex(self._indexes[core])

    def _on_current_core_changed(self, core: str) -> None:
        if core not in self._indexes:
            return
        self.stack.setCurrentIndex(self._indexes[core])

    def set_document(self, core: str, path: Path, text: str) -> None:
        editor = self._editors[core]
        editor.set_document(path, text)

    def set_template_source(self, core: str, path: Path | None) -> None:
        self._editors[core].set_template_source(path)

    def set_available_configs(self, core: str, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._editors[core].set_available_configs(items, selected)

    def set_available_templates(self, core: str, items: list[tuple[str, str]], selected: str | None = None) -> None:
        self._editors[core].set_available_templates(items, selected)

    def set_status(self, core: str, level: str, message: str) -> None:
        self._editors[core].set_status(level, message)

    def mark_saved(self, core: str, path: Path | None = None, text: str | None = None) -> None:
        self._editors[core].mark_saved(path, text)

    def is_dirty(self, core: str) -> bool:
        return self._editors[core].is_dirty()
