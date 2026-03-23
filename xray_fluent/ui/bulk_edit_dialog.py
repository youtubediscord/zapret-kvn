from __future__ import annotations

from PyQt6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout
from qfluentwidgets import BodyLabel, EditableComboBox, LineEdit, PrimaryPushButton, PushButton, SubtitleLabel, isDarkTheme


class BulkEditDialog(QDialog):
    def __init__(self, count: int, existing_groups: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Массовое редактирование")
        self.setModal(True)
        self.setMinimumWidth(420)
        bg = "#2b2b2b" if isDarkTheme() else "#f3f3f3"
        self.setStyleSheet(f"BulkEditDialog {{ background-color: {bg}; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(10)

        root.addWidget(SubtitleLabel("Массовое редактирование", self))
        root.addWidget(BodyLabel(f"Выбрано нод: {count}", self))

        root.addWidget(BodyLabel("Переместить в группу (пусто = пропустить)", self))
        self.group_combo = EditableComboBox(self)
        for g in existing_groups:
            self.group_combo.addItem(g)
        self.group_combo.setText("")
        root.addWidget(self.group_combo)

        root.addWidget(BodyLabel("Добавить теги (через запятую, пусто = пропустить)", self))
        self.add_tags_edit = LineEdit(self)
        self.add_tags_edit.setPlaceholderText("тег1, тег2")
        root.addWidget(self.add_tags_edit)

        root.addWidget(BodyLabel("Удалить теги (через запятую, пусто = пропустить)", self))
        self.remove_tags_edit = LineEdit(self)
        self.remove_tags_edit.setPlaceholderText("тег1, тег2")
        root.addWidget(self.remove_tags_edit)

        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.apply_btn = PrimaryPushButton("Применить", self)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.apply_btn)
        root.addLayout(row)

        self.cancel_btn.clicked.connect(self.reject)
        self.apply_btn.clicked.connect(self.accept)

    def get_operations(self) -> dict:
        group = self.group_combo.text().strip()
        raw_add = self.add_tags_edit.text().strip()
        raw_remove = self.remove_tags_edit.text().strip()
        add_tags = [t.strip() for t in raw_add.split(",") if t.strip()] if raw_add else []
        remove_tags = [t.strip() for t in raw_remove.split(",") if t.strip()] if raw_remove else []
        return {
            "group": group,
            "add_tags": add_tags,
            "remove_tags": remove_tags,
        }
