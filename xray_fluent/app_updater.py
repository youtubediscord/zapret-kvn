"""Self-update: check GitHub releases, download, extract, restart."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
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


def _powershell_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _write_utf8_bom_text(path: Path, text: str) -> None:
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))


def _resolve_extracted_app_dir(root: Path, exe_name: str) -> Path:
    if (root / exe_name).is_file():
        return root
    child_dirs = [path for path in root.iterdir() if path.is_dir()]
    if len(child_dirs) == 1 and (child_dirs[0] / exe_name).is_file():
        return child_dirs[0]
    for path in child_dirs:
        if (path / exe_name).is_file():
            return path
    return root


@dataclass(slots=True)
class AppUpdate:
    version: str
    tag: str
    download_url: str
    size: int
    notes: str
    digest_sha256: str = ""


_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")


def _parse_semver(version: str) -> tuple[int, int, int, list[str]] | None:
    match = _SEMVER_RE.search(version.strip().lstrip("v"))
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    prerelease = suffix.split(".") if suffix else []
    return int(major), int(minor), int(patch), prerelease


def _compare_prerelease(left: list[str], right: list[str]) -> int:
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1

    for left_part, right_part in zip(left, right):
        if left_part == right_part:
            continue
        left_is_num = left_part.isdigit()
        right_is_num = right_part.isdigit()
        if left_is_num and right_is_num:
            left_num = int(left_part)
            right_num = int(right_part)
            if left_num != right_num:
                return 1 if left_num > right_num else -1
            continue
        if left_is_num != right_is_num:
            return -1 if left_is_num else 1
        return 1 if left_part > right_part else -1

    if len(left) == len(right):
        return 0
    return 1 if len(left) > len(right) else -1


def _is_newer_version(latest: str, current: str) -> bool:
    latest_parts = _parse_semver(latest)
    current_parts = _parse_semver(current)
    if latest_parts is None or current_parts is None:
        return latest.strip().lstrip("v") != current.strip().lstrip("v")

    latest_core = latest_parts[:3]
    current_core = current_parts[:3]
    if latest_core != current_core:
        return latest_core > current_core
    return _compare_prerelease(latest_parts[3], current_parts[3]) > 0


def _extract_digest(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    parts = "".join(ch for ch in text if ch in "0123456789abcdef")
    return parts if len(parts) == 64 else ""


def _sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8", errors="replace")


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

            if not _is_newer_version(tag, APP_VERSION):
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
                return

            digest = _extract_digest(str(asset.get("digest") or ""))
            if not digest:
                asset_name = str(asset.get("name") or "")
                sidecar = None
                for suffix in (".sha256", ".dgst"):
                    expected = f"{asset_name}{suffix}".lower()
                    sidecar = next(
                        (
                            candidate for candidate in data.get("assets", [])
                            if str(candidate.get("name") or "").lower() == expected
                        ),
                        None,
                    )
                    if sidecar:
                        break
                if sidecar:
                    digest = _extract_digest(
                        _fetch_text(str(sidecar.get("browser_download_url") or ""))
                    )
            if not digest:
                self.error.emit(f"Релиз {tag} найден, но архив не содержит SHA-256")
                return

            self.result.emit(AppUpdate(
                version=tag.lstrip("v"),
                tag=tag,
                download_url=asset["browser_download_url"],
                size=asset.get("size", 0),
                notes=data.get("body", ""),
                digest_sha256=digest,
            ))
        except Exception as exc:
            self.error.emit(str(exc))
            return


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

    def __init__(
        self,
        update: AppUpdate,
        proxy_url: str | None = None,
        restart_in_tray: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._update = update
        self._proxy_url = proxy_url
        self._restart_in_tray = restart_in_tray

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
        tmp_dir: Path | None = None
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

            self.status.emit("Проверка архива...")
            expected_hash = _extract_digest(self._update.digest_sha256)
            if not expected_hash:
                self.error.emit("У релизного архива отсутствует SHA-256")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            real_hash = _sha256_file(zip_path)
            if real_hash.lower() != expected_hash.lower():
                self.error.emit("Контрольная сумма архива не совпадает")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            self.progress.emit(100)
            self.status.emit("Распаковка...")

            # Extract
            extract_dir = tmp_dir / "extracted"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            exe_name = "ZapretKVN.exe"
            source_dir = _resolve_extracted_app_dir(extract_dir, exe_name)
            if not (source_dir / exe_name).is_file():
                self.error.emit("Архив обновления не содержит ZapretKVN.exe")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            # Write restart script
            current_pid = os.getpid()
            app_dir = BASE_DIR
            script = tmp_dir / "_update.ps1"
            script_text = "\r\n".join([
                "$ErrorActionPreference = 'Stop'",
                f"$pidToWait = {current_pid}",
                f"$sourceDir = {_powershell_literal(str(source_dir))}",
                f"$appDir = {_powershell_literal(str(app_dir))}",
                f"$exePath = {_powershell_literal(str(app_dir / exe_name))}",
                f"$tempDir = {_powershell_literal(str(tmp_dir))}",
                "$preserveNames = @('data')",
                "$backupDir = Join-Path $tempDir '_backup'",
                "New-Item -ItemType Directory -Path $backupDir -Force | Out-Null",
                "for ($i = 0; $i -lt 120; $i++) {",
                "    if (-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)) { break }",
                "    Start-Sleep -Milliseconds 500",
                "}",
                "$proc = Get-Process -Id $pidToWait -ErrorAction SilentlyContinue",
                "if ($proc) { Stop-Process -Id $pidToWait -Force }",
                "$sourceItems = @(Get-ChildItem -LiteralPath $sourceDir -Force | Where-Object { $preserveNames -notcontains $_.Name })",
                "try {",
                "    Get-ChildItem -LiteralPath $appDir -Force | Where-Object { $preserveNames -notcontains $_.Name } | ForEach-Object {",
                "        Move-Item -LiteralPath $_.FullName -Destination $backupDir -Force",
                "    }",
                "    foreach ($item in $sourceItems) {",
                "        Copy-Item -LiteralPath $item.FullName -Destination $appDir -Recurse -Force",
                "    }",
                "}",
                "catch {",
                "    Get-ChildItem -LiteralPath $appDir -Force -ErrorAction SilentlyContinue | Where-Object { $preserveNames -notcontains $_.Name } | ForEach-Object {",
                "        Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue",
                "    }",
                "    Get-ChildItem -LiteralPath $backupDir -Force -ErrorAction SilentlyContinue | ForEach-Object {",
                "        Move-Item -LiteralPath $_.FullName -Destination $appDir -Force",
                "    }",
                "    throw",
                "}",
                (
                    "Start-Process -FilePath $exePath -ArgumentList '--tray'"
                    if self._restart_in_tray
                    else "Start-Process -FilePath $exePath"
                ),
                "Start-Sleep -Seconds 2",
                "Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue",
                "",
            ])
            _write_utf8_bom_text(script, script_text)

            # Launch script and exit
            subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-WindowStyle",
                    "Hidden",
                    "-File",
                    str(script),
                ],
                creationflags=0x08000000,
                close_fds=True,
            )

            self.finished_ok.emit()

        except Exception as exc:
            if tmp_dir is not None:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            self.error.emit(str(exc))
