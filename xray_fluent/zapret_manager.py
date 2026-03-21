"""Minimal winws2 (zapret2) process manager — preset-based, no orchestrator."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal

from .constants import BASE_DIR

log = logging.getLogger(__name__)

ZAPRET_DIR = BASE_DIR / "zapret"
WINWS2_EXE = ZAPRET_DIR / "exe" / "winws2.exe"
PRESETS_DIR = ZAPRET_DIR / "presets"

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


@dataclass
class PresetInfo:
    name: str
    description: str
    created: str
    modified: str
    arg_count: int
    file_path: Path


class ZapretManager(QObject):
    """Start / stop winws2.exe with a preset file."""

    started = pyqtSignal()
    stopped = pyqtSignal()
    error = pyqtSignal(str)
    log_line = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._health_timer = QTimer(self)
        self._health_timer.setInterval(3000)
        self._health_timer.timeout.connect(self._check_health)

    # ── public API ──────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.state() == QProcess.ProcessState.Running

    @staticmethod
    def list_presets() -> list[str]:
        """Return sorted list of available preset names (without .txt)."""
        if not PRESETS_DIR.is_dir():
            return []
        return sorted(
            p.stem for p in PRESETS_DIR.iterdir()
            if p.suffix == ".txt" and not p.name.startswith("_")
        )

    @staticmethod
    def preset_path(name: str) -> Path:
        return PRESETS_DIR / f"{name}.txt"

    @staticmethod
    def _parse_preset_args(preset: Path) -> list[str]:
        """Read preset file and return list of arguments (skip comments/blanks)."""
        args: list[str] = []
        text = preset.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                args.append(stripped)
        return args

    @staticmethod
    def _parse_metadata(text: str) -> dict[str, str]:
        """Extract metadata from comment headers."""
        meta: dict[str, str] = {}
        for line in text.splitlines()[:15]:  # only check first 15 lines
            stripped = line.strip()
            if not stripped.startswith("#"):
                if stripped:  # non-empty non-comment = end of headers
                    break
                continue
            for key in ("Preset", "Description", "Created", "Modified", "BuiltinVersion"):
                prefix = f"# {key}:"
                if stripped.startswith(prefix):
                    meta[key] = stripped[len(prefix):].strip()
                    break
        return meta

    @staticmethod
    def list_preset_infos() -> list[PresetInfo]:
        """Return list of PresetInfo for all presets, sorted by name."""
        if not PRESETS_DIR.is_dir():
            return []
        result = []
        for p in sorted(PRESETS_DIR.iterdir()):
            if p.suffix != ".txt" or p.name.startswith("_"):
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            meta = ZapretManager._parse_metadata(text)
            arg_count = sum(1 for line in text.splitlines()
                           if line.strip() and not line.strip().startswith("#"))
            result.append(PresetInfo(
                name=p.stem,
                description=meta.get("Description", ""),
                created=meta.get("Created", ""),
                modified=meta.get("Modified", ""),
                arg_count=arg_count,
                file_path=p,
            ))
        return result

    @staticmethod
    def read_preset(name: str) -> str:
        """Return full text content of a preset file."""
        path = PRESETS_DIR / f"{name}.txt"
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def save_preset(name: str, content: str, description: str = "") -> PresetInfo:
        """Write preset file with updated metadata headers."""
        path = PRESETS_DIR / f"{name}.txt"
        PRESETS_DIR.mkdir(parents=True, exist_ok=True)

        # Preserve original Created date if file exists
        created = ""
        if path.is_file():
            old_text = path.read_text(encoding="utf-8", errors="replace")
            old_meta = ZapretManager._parse_metadata(old_text)
            created = old_meta.get("Created", "")

        now = datetime.now().isoformat(timespec="seconds")
        if not created:
            created = now

        # Strip existing metadata headers from content
        lines = content.splitlines()
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("# Preset:") or stripped.startswith("# Description:") \
               or stripped.startswith("# Created:") or stripped.startswith("# Modified:"):
                continue
            body_lines.append(line)

        # Remove leading blank lines from body
        while body_lines and not body_lines[0].strip():
            body_lines.pop(0)

        header = f"# Preset: {name}\n# Description: {description}\n# Created: {created}\n# Modified: {now}\n\n"
        full_text = header + "\n".join(body_lines) + "\n"
        path.write_text(full_text, encoding="utf-8")

        arg_count = sum(1 for l in body_lines if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=name, description=description, created=created,
                         modified=now, arg_count=arg_count, file_path=path)

    @staticmethod
    def rename_preset(old_name: str, new_name: str) -> PresetInfo | None:
        """Rename preset file. Returns new PresetInfo or None on failure."""
        old_path = PRESETS_DIR / f"{old_name}.txt"
        new_path = PRESETS_DIR / f"{new_name}.txt"
        if not old_path.is_file() or new_path.exists():
            return None

        # Update # Preset: header inside the file
        text = old_path.read_text(encoding="utf-8", errors="replace")
        text = text.replace(f"# Preset: {old_name}", f"# Preset: {new_name}", 1)
        new_path.write_text(text, encoding="utf-8")
        old_path.unlink()

        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=new_name, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=new_path)

    @staticmethod
    def delete_preset(name: str) -> bool:
        """Delete preset file. Returns True if deleted."""
        path = PRESETS_DIR / f"{name}.txt"
        if path.is_file():
            path.unlink()
            return True
        return False

    @staticmethod
    def import_preset(source_path: Path) -> PresetInfo | None:
        """Import a preset file from external path. Handles name conflicts."""
        if not source_path.is_file():
            return None
        PRESETS_DIR.mkdir(parents=True, exist_ok=True)

        base_name = source_path.stem
        target = PRESETS_DIR / f"{base_name}.txt"
        counter = 1
        while target.exists():
            target = PRESETS_DIR / f"{base_name} ({counter}).txt"
            counter += 1

        shutil.copy2(source_path, target)

        # Read and return info
        text = target.read_text(encoding="utf-8", errors="replace")
        meta = ZapretManager._parse_metadata(text)
        arg_count = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        return PresetInfo(name=target.stem, description=meta.get("Description", ""),
                         created=meta.get("Created", ""), modified=meta.get("Modified", ""),
                         arg_count=arg_count, file_path=target)

    def start(self, preset_name: str) -> None:
        if self.running:
            self.stop()

        exe = WINWS2_EXE
        if not exe.exists():
            self.error.emit(f"winws2.exe не найден: {exe}")
            return

        preset = self.preset_path(preset_name)
        if not preset.exists():
            self.error.emit(f"Пресет не найден: {preset}")
            return

        # Parse preset and pass args directly (winws2 @file can't handle spaces in path)
        args = self._parse_preset_args(preset)
        if not args:
            self.error.emit(f"Пресет пустой: {preset_name}")
            return

        self._process = QProcess(self)
        self._process.setProgram(str(exe))
        self._process.setArguments(args)
        self._process.setWorkingDirectory(str(ZAPRET_DIR))
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_finished)

        log.info("zapret start: %s [%s] (%d args)", exe.name, preset_name, len(args))
        self.log_line.emit(f"[zapret] Запуск: {preset_name} ({len(args)} аргументов)")
        self._process.start()

        if not self._process.waitForStarted(5000):
            self.error.emit("Не удалось запустить winws2.exe")
            self._process = None
            return

        self._health_timer.start()
        self.started.emit()

    def stop(self) -> None:
        self._health_timer.stop()
        if self._process is None:
            return

        if self._process.state() == QProcess.ProcessState.Running:
            log.info("zapret stop")
            self._process.kill()
            self._process.waitForFinished(5000)

        self._process = None
        self.stopped.emit()

    # ── internals ───────────────────────────────────────────────

    def _drain_output(self) -> list[str]:
        """Read any remaining stdout/stderr from the process."""
        lines: list[str] = []
        if self._process is None:
            return lines
        for reader in (self._process.readAllStandardOutput,
                       self._process.readAllStandardError):
            data = reader().data()
            if data:
                for line in data.decode("utf-8", errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
        return lines

    def _on_stdout(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardOutput().data()
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_stderr(self) -> None:
        if self._process is None:
            return
        data = self._process.readAllStandardError().data()
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                self.log_line.emit(f"[zapret] {line.strip()}")

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._health_timer.stop()

        # Drain any buffered output before dropping the process reference
        remaining = self._drain_output()
        for line in remaining:
            self.log_line.emit(f"[zapret] {line}")

        log.info("zapret finished: code=%d status=%s", exit_code, exit_status.name)

        if exit_code != 0 or exit_status == QProcess.ExitStatus.CrashExit:
            detail = "\n".join(remaining) if remaining else "нет вывода"
            self.log_line.emit(
                f"[zapret] Процесс завершился с кодом {exit_code}"
            )
            self.error.emit(
                f"winws2 завершился с кодом {exit_code}\n{detail}"
            )

        self._process = None
        self.stopped.emit()

    def _check_health(self) -> None:
        if not self.running:
            self._health_timer.stop()
            self.stopped.emit()
