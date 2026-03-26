from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
import time
from collections import deque
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from .constants import RUNTIME_DIR, XRAY_CONFIG_FILE, XRAY_PATH_DEFAULT
from .path_utils import resolve_configured_path
from .subprocess_utils import (
    decode_output,
    pump_qt_events,
    result_output_text,
    run_text,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_started,
)


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
        self._starting = False
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines: deque[str] = deque(maxlen=20)
        self._last_exit_code: int | None = None
        self._last_exit_status = QProcess.ExitStatus.NormalExit
        self._last_exit_expected = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_exit_expected(self) -> bool:
        return self._last_exit_expected

    def start(self, xray_path: str, config: dict[str, Any]) -> bool:
        if not xray_path or not xray_path.strip():
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        exe = resolve_configured_path(
            xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            self.error.emit("Путь к Xray не настроен (укажите его в Настройки -> Пути к ядрам)")
            return False
        if not exe.is_file():
            self.error.emit(f"xray.exe не найден: {exe}")
            return False

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("Не удалось остановить предыдущий процесс Xray")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        required_ports = self._extract_required_ports(config)
        port_error = self._ensure_ports_available(required_ports)
        if port_error:
            self.error.emit(port_error)
            return False

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIG_FILE.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")

        self._starting = True
        self._startup_failure_reported = False
        self._runtime_error_reported = False
        self._last_output_lines.clear()
        self._process.setWorkingDirectory(str(exe.parent))
        self._process.setProgram(str(exe))
        self._process.setArguments(["run", "-c", str(XRAY_CONFIG_FILE)])
        self._process.start()

        if not wait_for_qprocess_started(self._process, 2000):
            self._starting = False
            self._report_startup_failure(f"Не удалось запустить Xray: {self._process.errorString()}")
            return False

        if not self._wait_until_ready(required_ports):
            self._starting = False
            return False

        self._starting = False
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
        if wait_for_qprocess_finished(self._process, 600):
            return True

        self._process.kill()
        if wait_for_qprocess_finished(self._process, 200):
            return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            return True

        self._stop_requested = False
        self.error.emit("Не удалось вовремя остановить процесс Xray")
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
                self._last_output_lines.append(clean)
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        message = f"Ошибка процесса Xray: {process_error.name} ({self._process.errorString()})"
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
        self._last_exit_expected = expected
        self._last_exit_code = exit_code
        self._last_exit_status = exit_status
        self._stop_requested = False
        self._running = False
        if self._starting and not expected:
            self._report_startup_failure(self._unexpected_exit_message(exit_code, exit_status, startup=True))
        elif not expected and not self._runtime_error_reported:
            self._runtime_error_reported = True
            self.error.emit(self._unexpected_exit_message(exit_code, exit_status, startup=False))
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)

    def _extract_required_ports(self, config: dict[str, Any]) -> dict[int, str]:
        port_roles: dict[int, str] = {}
        for inbound in config.get("inbounds", []):
            if not isinstance(inbound, dict):
                continue
            port = inbound.get("port")
            if not isinstance(port, int) or port <= 0:
                continue
            protocol = str(inbound.get("protocol") or "").strip().lower()
            tag = str(inbound.get("tag") or "").strip().lower()
            if protocol == "http":
                role = "HTTP"
            elif protocol == "socks":
                role = "SOCKS"
            elif tag == "api":
                role = "API"
            else:
                role = tag or protocol or "local"
            port_roles[port] = role
        return port_roles

    def _ensure_ports_available(self, port_roles: dict[int, str]) -> str | None:
        for port, role in port_roles.items():
            owner = self._find_listening_port_owner(port)
            if owner is None:
                continue
            pid, name = owner
            if pid > 0 and (name or "").strip().lower() == "xray.exe" and self._kill_pid(pid):
                sleep_with_events(0.5)
                if self._find_listening_port_owner(port) is None:
                    self.log_received.emit(f"[xray] terminated stale xray.exe PID {pid} on port {port}")
                    continue
            return self._port_conflict_message(port, role, pid, name)
        return None

    def _find_listening_port_owner(self, port: int) -> tuple[int, str] | None:
        try:
            result = run_text(["netstat", "-ano", "-p", "tcp"], timeout=5, check=False, creationflags=_CREATE_NO_WINDOW)
        except Exception:
            return None
        text = result_output_text(result)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[-2].upper()
            if state != "LISTENING":
                continue
            parsed_port = self._parse_port(parts[1])
            if parsed_port != port:
                continue
            try:
                pid = int(parts[-1])
            except ValueError:
                pid = 0
            return pid, self._lookup_process_name(pid)
        return None

    @staticmethod
    def _parse_port(endpoint: str) -> int | None:
        text = endpoint.strip()
        if text.startswith("[") and "]:" in text:
            _, port_text = text.rsplit("]:", 1)
        elif ":" in text:
            _, port_text = text.rsplit(":", 1)
        else:
            return None
        try:
            return int(port_text)
        except ValueError:
            return None

    @staticmethod
    def _lookup_process_name(pid: int) -> str:
        if pid <= 0:
            return ""
        try:
            result = run_text(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return ""
        rows = list(csv.reader(result_output_text(result).splitlines()))
        if not rows or not rows[0]:
            return ""
        name = rows[0][0].strip()
        if name.upper().startswith("INFO:"):
            return ""
        return name

    @staticmethod
    def _kill_pid(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            result = run_text(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                timeout=5,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return False
        return result.returncode == 0

    @staticmethod
    def _port_conflict_message(port: int, role: str, pid: int, name: str) -> str:
        prefix = f"{role} порт {port}" if role else f"Порт {port}"
        owner = "другим процессом"
        if name and pid > 0:
            owner = f"процессом {name} (PID {pid})"
        elif pid > 0:
            owner = f"PID {pid}"
        hint = ""
        if role == "HTTP":
            hint = " Измените HTTP порт в настройках или закройте конфликтующее приложение."
        elif role == "SOCKS":
            hint = " Измените SOCKS порт в настройках или закройте конфликтующее приложение."
        elif role == "API":
            hint = " Перезапустите приложение или завершите зависший Xray, который держит API порт."
        return f"{prefix} уже занят {owner}.{hint}"

    def _wait_until_ready(self, port_roles: dict[int, str], timeout_sec: float = 5.0) -> bool:
        if not port_roles:
            return True
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            pump_qt_events()
            if self._process.state() == QProcess.ProcessState.NotRunning:
                self._report_startup_failure(self._unexpected_exit_message(self._last_exit_code, self._last_exit_status, startup=True))
                return False
            if all(self._is_port_ready(port) for port in port_roles):
                return True
            sleep_with_events(0.1)
        not_ready = [f"{role} {port}" if role else str(port) for port, role in port_roles.items() if not self._is_port_ready(port)]
        self.stop(expected=True)
        details = ", ".join(not_ready) if not_ready else "нужные порты"
        self._report_startup_failure(f"Xray запустился, но не открыл нужные порты: {details}")
        return False

    @staticmethod
    def _is_port_ready(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            return False

    def _unexpected_exit_message(
        self,
        exit_code: int | None,
        exit_status: QProcess.ExitStatus,
        *,
        startup: bool,
    ) -> str:
        stage = "во время запуска" if startup else "неожиданно"
        detail = self._last_output_lines[-1].strip() if self._last_output_lines else ""
        if detail:
            return f"Xray завершился {stage}: {detail}"
        if exit_code is None:
            return f"Xray завершился {stage}."
        status_name = "CrashExit" if exit_status == QProcess.ExitStatus.CrashExit else "NormalExit"
        return f"Xray завершился {stage} с кодом {exit_code} ({status_name})."

    def _report_startup_failure(self, message: str) -> None:
        if self._startup_failure_reported:
            return
        self._startup_failure_reported = True
        self.error.emit(message)


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
