from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from ...constants import RUNTIME_DIR, SINGBOX_CONFIG_FILE, SINGBOX_PATH_DEFAULT
from ...path_utils import resolve_configured_path
from ...subprocess_utils import (
    decode_output,
    kill_processes_by_path,
    result_output_text,
    run_text_pumped,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_started,
)


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
        self._starting = False
        self._stop_requested = False
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines: deque[str] = deque(maxlen=20)
        self._last_exit_code: int | None = None
        self._last_exit_status = QProcess.ExitStatus.NormalExit

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

        tun_interface_name = self._extract_tun_interface_name(config)
        if not tun_interface_name:
            self.error.emit("sing-box config does not contain a TUN inbound interface_name")
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
        self._starting = True
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines.clear()

        # Try up to 3 times — wintun adapter may need time to be released
        for attempt in range(3):
            self._last_output_lines.clear()
            self._process.setWorkingDirectory(str(core_dir))
            self._process.setProgram(str(exe))
            self._process.setArguments(["run", "-c", str(SINGBOX_CONFIG_FILE), "-D", str(core_dir)])
            self._process.start()

            if not wait_for_qprocess_started(self._process, 4000):
                self._starting = False
                self._report_startup_failure(f"failed to start sing-box process: {self._process.errorString()}")
                return False

            if self._wait_until_tun_ready(tun_interface_name):
                self._starting = False
                self._mark_running()
                return True

            exited = self._process.state() == QProcess.ProcessState.NotRunning
            retryable = exited and self._startup_error_is_retryable()
            if not exited:
                self.stop(expected=True)

            if retryable and attempt < 2:
                self._wait_tun_released()
                self._starting = True
                continue

            self._starting = False
            if exited:
                self._report_startup_failure(
                    self._unexpected_exit_message(self._last_exit_code, self._last_exit_status, startup=True)
                )
            else:
                self._report_startup_failure(
                    f"sing-box started but TUN interface '{tun_interface_name}' did not become ready in time"
                )
            return False

        self._starting = False
        return False

    @staticmethod
    def _kill_orphaned(exe: Path) -> None:
        """Kill orphaned sing-box processes that hold the TUN adapter."""
        if os.name != "nt":
            return
        try:
            if kill_processes_by_path(exe.name, exe, timeout=5):
                sleep_with_events(1.0)
        except Exception:
            pass

    def stop(self, expected: bool = True) -> bool:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            self._starting = False
            return True

        self._stop_requested = expected
        self._process.terminate()
        if not wait_for_qprocess_finished(self._process, 3000):
            self._process.kill()
            wait_for_qprocess_finished(self._process, 2000)

        if self._process.state() != QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            self.error.emit("failed to stop sing-box process in time")
            return False

        # Wait for TUN adapter to be released by OS (active polling)
        self._starting = False
        self._wait_tun_released()
        return True

    @staticmethod
    def _wait_tun_released(max_wait: float = 10.0) -> None:
        """Poll until the TUN adapter is gone, up to max_wait seconds."""
        if os.name != "nt":
            return
        step = 0.3
        waited = 0.0
        while waited < max_wait:
            try:
                result = run_text_pumped(
                    ["netsh", "interface", "show", "interface"],
                    timeout=3,
                    creationflags=_CREATE_NO_WINDOW,
                )
                # Check if any xftun* adapter still exists
                if "xftun" not in result_output_text(result):
                    return  # TUN adapter gone
            except Exception:
                return  # can't check, proceed anyway
            sleep_with_events(step)
            waited += step

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
                self._last_output_lines.append(clean)
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        message = f"sing-box process error: {process_error.name} ({self._process.errorString()})"
        if self._starting:
            self._report_startup_failure(message)
            return
        if self._runtime_error_reported:
            return
        self._runtime_error_reported = True
        self.error.emit(message)

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        exit_status = QProcess.ExitStatus(_exit_status)
        expected = self._stop_requested
        self._last_exit_code = exit_code
        self._last_exit_status = exit_status
        self._stop_requested = False
        was_running = self._running
        self._running = False
        if self._starting and not expected:
            self._report_startup_failure(self._unexpected_exit_message(exit_code, exit_status, startup=True))
        elif was_running and not expected and not self._runtime_error_reported:
            self._runtime_error_reported = True
            self.error.emit(self._unexpected_exit_message(exit_code, exit_status, startup=False))
        self._starting = False
        self.stopped.emit(exit_code)
        if was_running:
            self.state_changed.emit(False)

    def _mark_running(self) -> None:
        if self._running:
            return
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    @staticmethod
    def _extract_tun_interface_name(config: dict[str, Any]) -> str:
        for inbound in config.get("inbounds") or []:
            if not isinstance(inbound, dict):
                continue
            if str(inbound.get("type") or "").strip().lower() != "tun":
                continue
            return str(inbound.get("interface_name") or "").strip()
        return ""

    def _wait_until_tun_ready(self, tun_interface_name: str, max_wait: float = 18.0) -> bool:
        if os.name != "nt" or not tun_interface_name:
            return True
        step = 0.25
        waited = 0.0
        while waited < max_wait:
            if self._process.state() == QProcess.ProcessState.NotRunning:
                return False
            if self._tun_interface_has_ipv4(tun_interface_name):
                return True
            sleep_with_events(step)
            waited += step
        return False

    @staticmethod
    def _tun_interface_has_ipv4(tun_interface_name: str) -> bool:
        escaped_name = tun_interface_name.replace("'", "''")
        script = (
            f"$ipv4 = Get-NetIPAddress -InterfaceAlias '{escaped_name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue "
            "| Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' } "
            "| Select-Object -First 1 IPAddress; "
            "if ($ipv4) { exit 0 } else { exit 1 }"
        )
        try:
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=4,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        return result.returncode == 0

    def _startup_error_is_retryable(self) -> bool:
        needles = ("already exists", "cannot create a file when that file already exists")
        for line in self._last_output_lines:
            text = line.lower()
            if any(needle in text for needle in needles):
                return True
        return False

    def _unexpected_exit_message(
        self,
        exit_code: int | None,
        exit_status: QProcess.ExitStatus,
        *,
        startup: bool,
    ) -> str:
        stage = "during startup" if startup else "unexpectedly"
        detail = self._last_output_lines[-1].strip() if self._last_output_lines else ""
        if detail:
            return f"sing-box exited {stage}: {detail}"
        if exit_code is None:
            return f"sing-box exited {stage}."
        status_name = "CrashExit" if exit_status == QProcess.ExitStatus.CrashExit else "NormalExit"
        return f"sing-box exited {stage} with code {exit_code} ({status_name})."

    def _report_startup_failure(self, message: str) -> None:
        if self._startup_failure_reported:
            return
        self._startup_failure_reported = True
        self.error.emit(message)


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
        result = run_text_pumped(
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
