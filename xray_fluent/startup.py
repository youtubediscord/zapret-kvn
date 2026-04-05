from __future__ import annotations

import os
import shlex
from pathlib import Path
import subprocess
import sys

if sys.platform == "win32":
    import winreg


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _run_command(args: list[str]) -> None:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(stderr or f"Command exited with code {result.returncode}")


def _run_schtasks(args: list[str]) -> None:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    schtasks = str(Path(system_root) / "System32" / "schtasks.exe")
    _run_command([schtasks, *args])


def _run_powershell(script: str) -> None:
    powershell = os.environ.get("WINDIR", r"C:\Windows") + r"\System32\WindowsPowerShell\v1.0\powershell.exe"
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(stderr or f"PowerShell exited with code {result.returncode}")


def _remove_legacy_run_key(app_name: str) -> None:
    if sys.platform != "win32":
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, app_name)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass


def _split_command(command: str) -> tuple[str, str]:
    parts = shlex.split(command, posix=False)
    if not parts:
        raise ValueError("Empty startup command")
    exe = parts[0].strip('"')
    args = subprocess.list2cmdline(parts[1:]) if len(parts) > 1 else ""
    return exe, args


def set_startup_enabled(app_name: str, enabled: bool, command: str) -> None:
    if sys.platform != "win32":
        return

    _remove_legacy_run_key(app_name)
    task_name = app_name
    if enabled:
        _run_schtasks([
            "/Create",
            "/F",
            "/TN",
            task_name,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/TR",
            command,
        ])
    else:
        _run_schtasks(["/Delete", "/F", "/TN", task_name])


def build_startup_command(start_in_tray: bool = True) -> str:
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return f'"{exe}" --tray' if start_in_tray else f'"{exe}"'

    base_dir = Path(__file__).resolve().parents[1]
    script = base_dir / "main.py"
    venv_pythonw = base_dir / ".venv" / "Scripts" / "pythonw.exe"
    python_exe = venv_pythonw if venv_pythonw.exists() else Path(sys.executable).resolve()
    return f'"{python_exe}" "{script}" --tray' if start_in_tray else f'"{python_exe}" "{script}"'
