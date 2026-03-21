from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget
from qfluentwidgets import (
    BreadcrumbBar,
    BodyLabel,
    CaptionLabel,
    CardWidget,
    FluentIcon as FIF,
    LineEdit,
    PlainTextEdit,
    PrimaryPushButton,
    StrongBodyLabel,
    TransparentToolButton,
)


class PresetEditWidget(QWidget):
    back_requested = pyqtSignal()
    save_requested = pyqtSignal(str, str, str)  # name, description, content

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._original_content = ""
        self._original_name = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # BreadcrumbBar
        self.breadcrumb = BreadcrumbBar(self)
        self.breadcrumb.addItem("zapret", "Zapret")
        self.breadcrumb.addItem("edit", "Редактирование")
        self.breadcrumb.currentItemChanged.connect(self._on_breadcrumb)
        root.addWidget(self.breadcrumb)

        # Top bar: back + title + save
        top = QHBoxLayout()
        top.setSpacing(8)
        self.back_btn = TransparentToolButton(FIF.RETURN, self)
        self.back_btn.setToolTip("Назад к списку")
        self.back_btn.clicked.connect(self._on_back)
        top.addWidget(self.back_btn)
        self.title_label = StrongBodyLabel("Редактирование пресета", self)
        top.addWidget(self.title_label)
        top.addStretch()
        self.save_btn = PrimaryPushButton(FIF.SAVE, "Сохранить", self)
        self.save_btn.clicked.connect(self._on_save)
        top.addWidget(self.save_btn)
        root.addLayout(top)

        # Metadata card
        meta_card = CardWidget(self)
        meta_layout = QVBoxLayout(meta_card)
        meta_layout.setContentsMargins(16, 12, 16, 12)
        meta_layout.setSpacing(8)

        name_row = QHBoxLayout()
        name_row.addWidget(BodyLabel("Название:", meta_card))
        self.name_edit = LineEdit(meta_card)
        self.name_edit.setPlaceholderText("Имя пресета")
        name_row.addWidget(self.name_edit, 1)
        meta_layout.addLayout(name_row)

        desc_row = QHBoxLayout()
        desc_row.addWidget(BodyLabel("Описание:", meta_card))
        self.desc_edit = LineEdit(meta_card)
        self.desc_edit.setPlaceholderText("Краткое описание (необязательно)")
        desc_row.addWidget(self.desc_edit, 1)
        meta_layout.addLayout(desc_row)

        self.meta_label = CaptionLabel("", meta_card)
        meta_layout.addWidget(self.meta_label)
        root.addWidget(meta_card)

        # Content editor
        self.editor = PlainTextEdit(self)
        self.editor.setPlaceholderText("Аргументы winws2, по одному на строку.\nСтроки с # — комментарии.")
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.editor.setFont(font)
        root.addWidget(self.editor, 1)

    def set_preset(self, name: str, description: str, content: str,
                   created: str = "", modified: str = "") -> None:
        """Load a preset into the editor."""
        self._original_name = name
        self._original_content = content

        self.name_edit.setText(name)
        self.desc_edit.setText(description)
        self.editor.setPlainText(content)
        self.title_label.setText(f"Редактирование: {name}" if name else "Новый пресет")

        # Update breadcrumb
        self.breadcrumb.clear()
        self.breadcrumb.addItem("zapret", "Zapret")
        self.breadcrumb.addItem("edit", name or "Новый пресет")

        # Meta info
        parts = []
        if created:
            parts.append(f"Создан: {created}")
        if modified:
            parts.append(f"Изменён: {modified}")
        self.meta_label.setText("  |  ".join(parts) if parts else "")

    def is_dirty(self) -> bool:
        """Check if content was modified."""
        return (self.editor.toPlainText() != self._original_content
                or self.name_edit.text() != self._original_name
                or self.desc_edit.text() != "")  # description changes count too

    def _on_save(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            return
        # Validate filename characters
        invalid = set('\\/:*?"<>|')
        if any(c in invalid for c in name):
            return
        desc = self.desc_edit.text().strip()
        content = self.editor.toPlainText()
        self.save_requested.emit(name, desc, content)
        self._original_name = name
        self._original_content = content

    def _on_back(self) -> None:
        if self.is_dirty():
            from qfluentwidgets import MessageBox
            box = MessageBox(
                "Несохранённые изменения",
                "Выйти без сохранения?",
                self.window(),
            )
            box.yesButton.setText("Выйти")
            box.cancelButton.setText("Остаться")
            if not box.exec():
                return
        self.back_requested.emit()

    def _on_breadcrumb(self, key: str) -> None:
        if key == "zapret":
            self._on_back()
