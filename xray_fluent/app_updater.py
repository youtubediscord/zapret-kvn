"""Self-update: check GitHub releases, download, extract, restart."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import APP_VERSION, BASE_DIR

GITHUB_REPO = "youtubediscord/zapret-kvn"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
USER_AGENT = f"ZapretKVN/{APP_VERSION}"


@dataclass(slots=True)
class AppUpdate:
    version: str
    tag: str
    download_url: str
    size: int
    notes: str


def _parse_version(v: str) -> tuple[int, ...]:
    clean = v.lstrip("v").split("-")[0]
    return tuple(int(x) for x in clean.split(".") if x.isdigit())


class UpdateChecker(QThread):
    """Check GitHub for a newer release."""

    result = pyqtSignal(object)  # AppUpdate | None

    def run(self) -> None:
        try:
            req = Request(GITHUB_API, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            tag = data.get("tag_name", "")
            remote = _parse_version(tag)
            local = _parse_version(APP_VERSION)

            if remote <= local:
                self.result.emit(None)
                return

            asset = None
            for a in data.get("assets", []):
                name = a.get("name", "").lower()
                if name.endswith(".zip") and "windows" in name and "x64" in name:
                    asset = a
                    break

            if not asset:
                self.result.emit(None)
                return

            self.result.emit(AppUpdate(
                version=tag.lstrip("v"),
                tag=tag,
                download_url=asset["browser_download_url"],
                size=asset.get("size", 0),
                notes=data.get("body", ""),
            ))
        except Exception:
            self.result.emit(None)


class UpdateDownloader(QThread):
    """Download and extract update, then launch restart script."""

    progress = pyqtSignal(int)  # percent 0-100
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, update: AppUpdate, parent=None):
        super().__init__(parent)
        self._update = update

    def run(self) -> None:
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="zapretkvn_update_"))
            zip_path = tmp_dir / "update.zip"

            # Download
            req = Request(self._update.download_url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=120) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                with open(zip_path, "wb") as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            self.progress.emit(int(downloaded * 100 / total))

            self.progress.emit(100)

            # Extract
            extract_dir = tmp_dir / "extracted"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            # Write restart script
            exe_name = "ZapretKVN.exe"
            app_dir = str(BASE_DIR)
            src_dir = str(extract_dir)
            script = tmp_dir / "_update.bat"
            script.write_text(
                "@echo off\r\n"
                "echo Updating zapret kvn...\r\n"
                "timeout /t 2 /nobreak >nul\r\n"
                f'taskkill /F /IM {exe_name} 2>nul\r\n'
                "timeout /t 1 /nobreak >nul\r\n"
                f'xcopy /E /Y /Q "{src_dir}\\*" "{app_dir}\\"\r\n'
                "echo Update complete. Restarting...\r\n"
                f'start "" "{app_dir}\\{exe_name}"\r\n'
                f'rmdir /S /Q "{str(tmp_dir)}"\r\n',
                encoding="ascii",
            )

            # Launch script and exit
            subprocess.Popen(
                ["cmd", "/c", str(script)],
                creationflags=0x08000000,
                close_fds=True,
            )

            self.finished_ok.emit()

        except Exception as exc:
            self.error.emit(str(exc))
