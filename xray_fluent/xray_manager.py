from __future__ import annotations

import json
import os
import subprocess
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from .constants import RUNTIME_DIR, XRAY_CONFIG_FILE, XRAY_PATH_DEFAULT
from .path_utils import resolve_configured_path
from .subprocess_utils import decode_output, result_output_text, run_text


class XrayManager(QObject):
    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_ready_read)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)
        self._running = False
        self._stop_requested = False

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, xray_path: str, config: dict[str, Any]) -> bool:
        if not xray_path or not xray_path.strip():
            self.error.emit("Xray path is not configured (set it in Settings → Core paths)")
            return False
        exe = resolve_configured_path(
            xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("Xray path is not configured (set it in Settings → Core paths)")
            return False
        if not exe.is_file():
            self.error.emit(f"xray.exe not found: {exe}")
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIG_FILE.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("failed to stop previous xray process")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        self._process.setProgram(str(exe))
        self._process.setArguments(["run", "-c", str(XRAY_CONFIG_FILE)])
        self._process.start()

        if not self._process.waitForStarted(2000):
            self.error.emit(f"failed to start xray process: {self._process.errorString()}")
            return False

        # Brief yield to let process initialize and detect early crashes
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        if app:
            app.processEvents()
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self.error.emit("xray process exited right after start")
            return False

        return True

    def stop(self, expected: bool = True) -> bool:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        self._stop_requested = expected
        self._process.terminate()
        # Non-blocking wait: process Qt events to keep UI responsive
        from PyQt6.QtWidgets import QApplication
        for _ in range(6):  # 6 × 100ms = 600ms max
            if self._process.waitForFinished(100):
                return True
            app = QApplication.instance()
            if app:
                app.processEvents()

        self._process.kill()
        if self._process.waitForFinished(200):
            return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            return True

        self._stop_requested = False
        self.error.emit("failed to stop xray process in time")
        return False

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        if isinstance(raw, (bytes, bytearray)):
            text = decode_output(bytes(raw))
        else:
            text = str(raw)
        for line in text.splitlines():
            clean = line.rstrip()
            if clean:
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        message = f"xray process error: {process_error.name} ({self._process.errorString()})"
        self.error.emit(message)

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        self._stop_requested = False
        self._running = False
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)


def get_xray_version(xray_path: str) -> str | None:
    exe = resolve_configured_path(
        xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        return None
    if not exe.exists():
        return None
    try:
        result = run_text(
            [str(exe), "version"],
            timeout=3,
            check=False,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None

    lines = result_output_text(result).splitlines()
    if not lines:
        return None
    return lines[0].strip()
