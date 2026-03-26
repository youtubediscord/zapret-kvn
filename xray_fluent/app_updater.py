"""Self-update: check GitHub releases, download, extract, restart."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
import zipfile  # kept for legacy .zip support
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request

from .http_utils import build_opener, urlopen

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
    error = pyqtSignal(str)

    def run(self) -> None:
        try:
            req = Request(GITHUB_API, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=15) as resp:
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
                self.error.emit(f"Релиз {tag} найден, но отсутствует Windows zip-архив")
                self.result.emit(None)
                return

            self.result.emit(AppUpdate(
                version=tag.lstrip("v"),
                tag=tag,
                download_url=asset["browser_download_url"],
                size=asset.get("size", 0),
                notes=data.get("body", ""),
            ))
        except Exception as exc:
            self.error.emit(str(exc))
            self.result.emit(None)


_log = logging.getLogger(__name__)

_DOWNLOAD_TIMEOUT = 30  # seconds — per socket operation (connect + each read)
_NUM_SEGMENTS = 4       # parallel download segments
_CHUNK_SIZE = 1024 * 1024  # 1 MB


class UpdateDownloader(QThread):
    """Download and extract update, then launch restart script."""

    progress = pyqtSignal(int)       # percent 0-100
    status = pyqtSignal(str)         # human-readable status message
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, update: AppUpdate, proxy_url: str | None = None, parent=None):
        super().__init__(parent)
        self._update = update
        self._proxy_url = proxy_url

    # ── download helpers ────────────────────────────────────────

    def _build_opener(self, proxy_url: str | None) -> urllib.request.OpenerDirector:
        if proxy_url:
            handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            return build_opener(handler)
        return build_opener()

    def _supports_range(self, url: str, opener: urllib.request.OpenerDirector) -> tuple[bool, int]:
        """HEAD request to check Range support and get Content-Length."""
        req = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            accepts = resp.headers.get("Accept-Ranges", "").lower()
            length = int(resp.headers.get("Content-Length", 0))
            return accepts == "bytes" and length > 0, length

    def _download_segment(
        self,
        url: str,
        proxy_url: str | None,
        start: int,
        end: int,
        seg_path: Path,
        seg_index: int,
        lock: threading.Lock,
        progress_arr: list[int],
        total: int,
    ) -> None:
        """Download one segment with Range header."""
        opener = self._build_opener(proxy_url)
        req = Request(url, headers={
            "User-Agent": USER_AGENT,
            "Range": f"bytes={start}-{end}",
        })
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            with open(seg_path, "wb") as f:
                while True:
                    chunk = resp.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    with lock:
                        progress_arr[seg_index] += len(chunk)
                        done = sum(progress_arr)
                        self.progress.emit(int(done * 100 / total))

    def _download_single(self, url: str, opener: urllib.request.OpenerDirector, zip_path: Path) -> None:
        """Single-connection fallback download."""
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(_CHUNK_SIZE)
                    if not chunk:
                        if downloaded == 0:
                            raise TimeoutError("Сервер не отдаёт данные")
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        self.progress.emit(int(downloaded * 100 / total))

    def _download(self, zip_path: Path, proxy_url: str | None) -> None:
        """Download update zip with multi-segment acceleration.

        Tries parallel Range-based download first; falls back to single
        connection if the server doesn't support Range requests.
        """
        url = self._update.download_url
        opener = self._build_opener(proxy_url)

        # Check if server supports Range requests
        try:
            supports_range, total = self._supports_range(url, opener)
        except Exception:
            supports_range, total = False, 0

        if not supports_range or total == 0 or total < _NUM_SEGMENTS * _CHUNK_SIZE:
            _log.info("Server does not support Range or file too small — single download")
            self._download_single(url, opener, zip_path)
            return

        # Split into segments
        seg_size = total // _NUM_SEGMENTS
        segments: list[tuple[int, int]] = []
        for i in range(_NUM_SEGMENTS):
            start = i * seg_size
            end = total - 1 if i == _NUM_SEGMENTS - 1 else (i + 1) * seg_size - 1
            segments.append((start, end))

        # Prepare temp segment files
        seg_dir = zip_path.parent / "_segments"
        seg_dir.mkdir(exist_ok=True)
        seg_paths = [seg_dir / f"seg_{i}" for i in range(_NUM_SEGMENTS)]

        lock = threading.Lock()
        progress_arr = [0] * _NUM_SEGMENTS

        # Download segments in parallel
        try:
            with ThreadPoolExecutor(max_workers=_NUM_SEGMENTS) as pool:
                futures = []
                for i, (start, end) in enumerate(segments):
                    fut = pool.submit(
                        self._download_segment,
                        url, proxy_url, start, end,
                        seg_paths[i], i, lock, progress_arr, total,
                    )
                    futures.append(fut)

                # Re-raise any segment exception
                for fut in futures:
                    fut.result()

            # Concatenate segments into final file
            with open(zip_path, "wb") as out:
                for sp in seg_paths:
                    with open(sp, "rb") as seg_f:
                        shutil.copyfileobj(seg_f, out)
        finally:
            # Clean up segment temp files
            shutil.rmtree(seg_dir, ignore_errors=True)

    # ── main thread entry ───────────────────────────────────────

    def run(self) -> None:
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="zapretkvn_update_"))
            zip_path = tmp_dir / "update.zip"

            downloaded_ok = False

            # Attempt 1: through proxy (if available)
            if self._proxy_url:
                self.status.emit("Загрузка через прокси...")
                try:
                    self._download(zip_path, self._proxy_url)
                    downloaded_ok = True
                except Exception as exc:
                    _log.warning("Proxy download failed: %s", exc)
                    self.status.emit(
                        "Прокси-сервер недоступен, пробую напрямую..."
                    )
                    self.progress.emit(0)
                    # clean partial file
                    if zip_path.exists():
                        zip_path.unlink()

            # Attempt 2: direct (no proxy)
            if not downloaded_ok:
                self.status.emit("Загрузка напрямую...")
                try:
                    self._download(zip_path, None)
                    downloaded_ok = True
                except Exception as exc:
                    _log.warning("Direct download failed: %s", exc)

            if not downloaded_ok:
                msg = (
                    "Не удалось скачать обновление.\n"
                    "Переключитесь на рабочий сервер и попробуйте снова."
                )
                if self._proxy_url:
                    msg = (
                        "Не удалось скачать обновление ни через прокси, ни напрямую.\n"
                        "Переключитесь на рабочий сервер и попробуйте снова."
                    )
                self.error.emit(msg)
                # cleanup
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            self.progress.emit(100)
            self.status.emit("Распаковка...")

            # Extract
            extract_dir = tmp_dir / "extracted"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            # Write restart script
            exe_name = "ZapretKVN.exe"
            current_pid = os.getpid()
            app_dir = str(BASE_DIR)
            src_dir = str(extract_dir)
            script = tmp_dir / "_update.bat"
            script.write_text(
                "@echo off\r\n"
                "chcp 65001 >nul\r\n"
                "echo Updating zapret kvn...\r\n"
                "timeout /t 2 /nobreak >nul\r\n"
                f'taskkill /F /PID {current_pid} 2>nul\r\n'
                "timeout /t 1 /nobreak >nul\r\n"
                f'xcopy /E /Y /Q "{src_dir}\\*" "{app_dir}\\"\r\n'
                "echo Update complete. Restarting...\r\n"
                f'start "" "{app_dir}\\{exe_name}"\r\n'
                f'rmdir /S /Q "{str(tmp_dir)}"\r\n',
                encoding="utf-8-sig",
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
