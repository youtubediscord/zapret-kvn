from __future__ import annotations

import locale
import os
import subprocess
import time
from pathlib import Path
from typing import Any


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def decode_output(data: bytes | None) -> str:
    if not data:
        return ""
    encodings: list[str] = ["utf-8"]
    if os.name == "nt":
        encodings.extend(["cp866", locale.getpreferredencoding(False), "cp1251"])
    for encoding in dict.fromkeys(encodings):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def result_output_text(result: subprocess.CompletedProcess[bytes]) -> str:
    return decode_output(result.stdout or result.stderr or b"")


def run_text(
    command: list[str],
    *,
    timeout: float,
    check: bool = False,
    creationflags: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    kwargs: dict[str, int | bool | float] = {
        "capture_output": True,
        "text": False,
        "timeout": timeout,
        "check": check,
    }
    if creationflags is not None:
        kwargs["creationflags"] = creationflags
    return subprocess.run(command, **kwargs)


def pump_qt_events() -> None:
    try:
        from PyQt6.QtWidgets import QApplication
    except Exception:
        return

    app = QApplication.instance()
    if app is not None:
        app.processEvents()


def sleep_with_events(duration_sec: float, *, step_sec: float = 0.05) -> None:
    deadline = time.monotonic() + max(0.0, duration_sec)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        pump_qt_events()
        time.sleep(min(step_sec, remaining))


def _wait_for_qprocess_call(
    process: Any,
    method_name: str,
    timeout_ms: int,
    *,
    slice_ms: int = 50,
) -> bool:
    remaining = max(0, int(timeout_ms))
    waiter = getattr(process, method_name)

    while remaining > 0:
        step = min(slice_ms, remaining)
        if waiter(step):
            return True
        pump_qt_events()
        remaining -= step

    pump_qt_events()
    return False


def wait_for_qprocess_started(process: Any, timeout_ms: int) -> bool:
    return _wait_for_qprocess_call(process, "waitForStarted", timeout_ms)


def wait_for_qprocess_finished(process: Any, timeout_ms: int) -> bool:
    return _wait_for_qprocess_call(process, "waitForFinished", timeout_ms)


def wait_for_qprocess_ready_read(process: Any, timeout_ms: int) -> bool:
    return _wait_for_qprocess_call(process, "waitForReadyRead", timeout_ms)


def is_same_path(left: str | Path | None, right: str | Path | None) -> bool:
    if not left or not right:
        return False
    try:
        return Path(left).resolve() == Path(right).resolve()
    except Exception:
        return False


def kill_processes_by_path(process_name: str, executable_path: str | Path, *, timeout: float = 5.0) -> bool:
    if os.name != "nt":
        return False
    target = Path(executable_path)
    target_text = str(target).replace("'", "''")
    script = (
        "$matches = @(Get-CimInstance Win32_Process | "
        f"Where-Object {{ $_.Name -eq '{process_name}' -and $_.ExecutablePath -eq '{target_text}' }}); "
        "$matches | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "
        "Write-Output $matches.Count"
    )
    result = run_text(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        return False
    return result_output_text(result).strip() not in {"", "0"}
