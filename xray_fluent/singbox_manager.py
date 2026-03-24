from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from .constants import RUNTIME_DIR, SINGBOX_CONFIG_FILE, SINGBOX_PATH_DEFAULT
from .path_utils import resolve_configured_path


class SingBoxManager(QObject):
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

    def start(self, singbox_path: str, config: dict[str, Any]) -> bool:
        exe = resolve_configured_path(
            singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("sing-box path is not configured (set it in Settings → Core paths)")
            return False
        if not exe.is_file():
            self.error.emit(f"sing-box.exe not found: {exe}")
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        SINGBOX_CONFIG_FILE.write_text(
            json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8"
        )

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("failed to stop previous sing-box process")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        # Kill any orphaned sing-box processes to free the TUN adapter
        self._kill_orphaned(exe)

        # Set working directory to core/ so sing-box can find wintun.dll
        core_dir = exe.parent

        # Try up to 3 times — wintun adapter may need time to be released
        for attempt in range(3):
            self._process.setWorkingDirectory(str(core_dir))
            self._process.setProgram(str(exe))
            self._process.setArguments(["run", "-c", str(SINGBOX_CONFIG_FILE), "-D", str(core_dir)])
            self._process.start()

            if not self._process.waitForStarted(4000):
                self.error.emit(f"failed to start sing-box process: {self._process.errorString()}")
                return False

            # TUN adapter creation can take several seconds
            self._process.waitForReadyRead(5000)
            # Give extra time for potential FATAL errors
            time.sleep(0.5)
            if self._process.state() == QProcess.ProcessState.NotRunning:
                # Check if it was "file already exists" — retry after pause
                if attempt < 2:
                    time.sleep(3)
                    continue
                self.error.emit("sing-box process exited right after start")
                return False

            return True

        return False

    @staticmethod
    def _kill_orphaned(exe: Path) -> None:
        """Kill orphaned sing-box processes that hold the TUN adapter."""
        if os.name != "nt":
            return
        exe_name = exe.name
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", exe_name],
                capture_output=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                time.sleep(1)  # give OS time to release the TUN adapter
        except Exception:
            pass

    def stop(self, expected: bool = True) -> bool:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        self._stop_requested = expected
        self._process.terminate()
        if self._process.waitForFinished(3000):
            time.sleep(1)  # give OS time to release TUN adapter
            return True

        self._process.kill()
        if self._process.waitForFinished(2000):
            time.sleep(1)
            return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            return True

        self._stop_requested = False
        self.error.emit("failed to stop sing-box process in time")
        return False

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("utf-8", errors="replace")
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
        message = f"sing-box process error: {process_error.name} ({self._process.errorString()})"
        self.error.emit(message)

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        self._stop_requested = False
        self._running = False
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)


def get_singbox_version(singbox_path: str) -> str | None:
    exe = resolve_configured_path(
        singbox_path,
        default_path=SINGBOX_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        return None
    if not exe.exists():
        return None
    try:
        result = subprocess.run(
            [str(exe), "version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None

    lines = (result.stdout or result.stderr or "").splitlines()
    if not lines:
        return None
    return lines[0].strip()
