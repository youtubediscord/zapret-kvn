from __future__ import annotations

from PyQt6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout
from qfluentwidgets import BodyLabel, PasswordLineEdit, PrimaryPushButton, PushButton, SubtitleLabel, isDarkTheme


class PasswordDialog(QDialog):
    def __init__(self, title: str = "Разблокировать", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(360)
        bg = "#2b2b2b" if isDarkTheme() else "#f3f3f3"
        self.setStyleSheet(f"PasswordDialog {{ background-color: {bg}; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(10)

        root.addWidget(SubtitleLabel(title, self))
        root.addWidget(BodyLabel("Введите мастер-пароль", self))

        self.password_edit = PasswordLineEdit(self)
        self.password_edit.setPlaceholderText("Пароль")
        self.password_edit.returnPressed.connect(self.accept)
        root.addWidget(self.password_edit)

        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.ok_btn = PrimaryPushButton("OK", self)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.ok_btn)
        root.addLayout(row)

        self.cancel_btn.clicked.connect(self.reject)
        self.ok_btn.clicked.connect(self.accept)

    def password(self) -> str:
        return self.password_edit.text().strip()
