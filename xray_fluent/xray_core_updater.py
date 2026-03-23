from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.request import Request

from .http_utils import urlopen
import zipfile

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import XRAY_GITHUB_RELEASES_API, XRAY_PATH_DEFAULT
from .path_utils import resolve_configured_path
from .update_checker import check_update
from .xray_manager import get_xray_version


@dataclass(slots=True)
class XrayCoreRelease:
    version: str
    channel: str
    url: str
    digest_sha256: str = ""
    notes: str = ""


@dataclass(slots=True)
class XrayCoreUpdateResult:
    status: str  # up_to_date | available | updated | error
    message: str
    channel: str
    current_version: str
    latest_version: str
    updated: bool = False


_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-+]([0-9A-Za-z.-]+))?")


def _extract_version(text: str) -> str:
    value = text.strip().lstrip("v")
    match = _SEMVER_RE.search(value)
    if not match:
        return value
    major, minor, patch, suffix = match.groups()
    if suffix:
        return f"{major}.{minor}.{patch}-{suffix}"
    return f"{major}.{minor}.{patch}"


def _version_key(version: str) -> tuple[int, int, int, int, str] | None:
    match = _SEMVER_RE.search(version.strip().lstrip("v"))
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    stable_flag = 1 if not suffix else 0
    return int(major), int(minor), int(patch), stable_flag, suffix or ""


def _is_newer(latest: str, current: str) -> bool:
    latest_key = _version_key(latest)
    current_key = _version_key(current)
    if latest_key is None or current_key is None:
        return _extract_version(latest) != _extract_version(current)
    return latest_key > current_key


def _normalize_channel(value: str) -> str:
    normalized = value.lower().strip()
    if normalized in {"stable", "beta", "nightly"}:
        return normalized
    return "stable"


def _request_json(url: str) -> object:
    request = Request(url, headers={"User-Agent": "ZapretKVN/0.4"})
    with urlopen(request, timeout=12) as response:
        return json.loads(response.read().decode("utf-8"))


def _pick_release_from_github(releases: list[dict], channel: str) -> dict | None:
    if channel == "stable":
        for release in releases:
            if not bool(release.get("prerelease")):
                return release
        return None

    prereleases = [release for release in releases if bool(release.get("prerelease"))]
    if not prereleases:
        return None

    if channel == "beta":
        for release in prereleases:
            text = f"{release.get('tag_name', '')} {release.get('name', '')}".lower()
            if "beta" in text or "rc" in text:
                return release
        return prereleases[0]

    # nightly
    for release in prereleases:
        text = f"{release.get('tag_name', '')} {release.get('name', '')}".lower()
        if "nightly" in text or "dev" in text:
            return release
    return prereleases[0]


def _find_github_asset(release: dict, name: str) -> dict | None:
    for asset in release.get("assets", []):
        if str(asset.get("name") or "").lower() == name.lower():
            return asset
    return None


def _extract_digest(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    match = re.search(r"([a-f0-9]{64})", text)
    return match.group(1) if match else ""


def _fetch_dgst_hash(url: str) -> str:
    request = Request(url, headers={"User-Agent": "ZapretKVN/0.4"})
    with urlopen(request, timeout=12) as response:
        body = response.read().decode("utf-8", errors="replace")
    return _extract_digest(body)


def resolve_xray_release(channel: str, feed_url: str = "") -> XrayCoreRelease | None:
    normalized_channel = _normalize_channel(channel)

    if feed_url.strip():
        info = check_update(feed_url.strip(), normalized_channel)
        if not info:
            return None
        return XrayCoreRelease(
            version=info.version,
            channel=normalized_channel,
            url=info.url,
            digest_sha256=info.digest_sha256,
            notes=info.notes,
        )

    payload = _request_json(XRAY_GITHUB_RELEASES_API)
    if not isinstance(payload, list):
        return None
    release = _pick_release_from_github([item for item in payload if isinstance(item, dict)], normalized_channel)
    if not release:
        return None

    zip_asset = _find_github_asset(release, "Xray-windows-64.zip")
    if not zip_asset:
        return None

    digest = _extract_digest(str(zip_asset.get("digest") or ""))
    if not digest:
        dgst_asset = _find_github_asset(release, "Xray-windows-64.zip.dgst")
        if dgst_asset:
            digest = _fetch_dgst_hash(str(dgst_asset.get("browser_download_url") or ""))

    version = str(release.get("tag_name") or release.get("name") or "")
    return XrayCoreRelease(
        version=_extract_version(version),
        channel=normalized_channel,
        url=str(zip_asset.get("browser_download_url") or ""),
        digest_sha256=digest,
        notes=str(release.get("body") or ""),
    )


def _download_file(url: str, destination: Path, on_progress=None) -> None:
    """Download file with optional progress callback(downloaded, total)."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(url, headers={"User-Agent": "ZapretKVN/0.4"})
    with urlopen(request, timeout=120) as response:
        total = int(response.headers.get("Content-Length", 0))
        downloaded = 0
        with open(destination, "wb") as file:
            while True:
                chunk = response.read(1024 * 1024)  # 1 MB
                if not chunk:
                    break
                file.write(chunk)
                downloaded += len(chunk)
                if on_progress and total > 0:
                    on_progress(downloaded, total)


def _sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _find_file(root: Path, file_name: str) -> Path | None:
    for path in root.rglob(file_name):
        if path.is_file():
            return path
    return None


def _install_zip_archive(archive_path: Path, target_xray_path: Path) -> None:
    target_dir = target_xray_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="xray_core_extract_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        with zipfile.ZipFile(archive_path, "r") as archive:
            archive.extractall(temp_dir)

        new_xray = _find_file(temp_dir, "xray.exe")
        if not new_xray:
            raise RuntimeError("xray.exe not found in archive")

        backup_path = target_xray_path.with_suffix(".exe.bak")
        if target_xray_path.exists():
            shutil.copy2(target_xray_path, backup_path)

        temp_target = target_xray_path.with_suffix(".exe.new")
        shutil.copy2(new_xray, temp_target)
        temp_target.replace(target_xray_path)

        for optional_name in ("geoip.dat", "geosite.dat", "wintun.dll"):
            src = _find_file(temp_dir, optional_name)
            if src:
                shutil.copy2(src, target_dir / optional_name)


def check_and_update_xray_core(
    xray_path: str,
    channel: str,
    feed_url: str = "",
    apply_update: bool = False,
    on_progress=None,
) -> XrayCoreUpdateResult:
    exe = resolve_configured_path(
        xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        exe = XRAY_PATH_DEFAULT
    if not exe.exists():
        return XrayCoreUpdateResult(
            status="error",
            message=f"xray.exe не найден: {exe}",
            channel=_normalize_channel(channel),
            current_version="",
            latest_version="",
            updated=False,
        )

    current_text = get_xray_version(str(exe)) or ""
    current_version = _extract_version(current_text)

    try:
        release = resolve_xray_release(channel, feed_url)
    except Exception as exc:
        return XrayCoreUpdateResult(
            status="error",
            message=f"Не удалось получить информацию о релизе: {exc}",
            channel=_normalize_channel(channel),
            current_version=current_version,
            latest_version="",
            updated=False,
        )

    if not release or not release.url:
        return XrayCoreUpdateResult(
            status="error",
            message="Информация о релизе не найдена",
            channel=_normalize_channel(channel),
            current_version=current_version,
            latest_version="",
            updated=False,
        )

    latest_version = _extract_version(release.version)
    if current_version and not _is_newer(latest_version, current_version):
        return XrayCoreUpdateResult(
            status="up_to_date",
            message=f"Xray core актуален ({current_version})",
            channel=release.channel,
            current_version=current_version,
            latest_version=latest_version,
            updated=False,
        )

    if not apply_update:
        return XrayCoreUpdateResult(
            status="available",
            message=f"Доступно обновление Xray: {latest_version}",
            channel=release.channel,
            current_version=current_version,
            latest_version=latest_version,
            updated=False,
        )

    with tempfile.TemporaryDirectory(prefix="xray_core_update_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        archive_path = temp_dir / "Xray-windows-64.zip"
        try:
            _download_file(release.url, archive_path, on_progress=on_progress)
        except Exception as exc:
            return XrayCoreUpdateResult(
                status="error",
                message=f"Ошибка загрузки: {exc}",
                channel=release.channel,
                current_version=current_version,
                latest_version=latest_version,
                updated=False,
            )

        expected_hash = _extract_digest(release.digest_sha256)
        if expected_hash:
            real_hash = _sha256_file(archive_path)
            if real_hash.lower() != expected_hash.lower():
                return XrayCoreUpdateResult(
                    status="error",
                    message="Контрольная сумма архива не совпадает",
                    channel=release.channel,
                    current_version=current_version,
                    latest_version=latest_version,
                    updated=False,
                )

        try:
            _install_zip_archive(archive_path, exe)
        except Exception as exc:
            return XrayCoreUpdateResult(
                status="error",
                message=f"Ошибка установки: {exc}",
                channel=release.channel,
                current_version=current_version,
                latest_version=latest_version,
                updated=False,
            )

    refreshed = _extract_version(get_xray_version(str(exe)) or latest_version)
    return XrayCoreUpdateResult(
        status="updated",
        message=f"Xray core обновлён до {refreshed}",
        channel=release.channel,
        current_version=current_version,
        latest_version=refreshed,
        updated=True,
    )


class XrayCoreUpdateWorker(QThread):
    done = pyqtSignal(object)
    progress = pyqtSignal(int)  # percent 0-100

    def __init__(
        self,
        xray_path: str,
        channel: str,
        feed_url: str,
        apply_update: bool,
    ):
        super().__init__()
        self._xray_path = xray_path
        self._channel = channel
        self._feed_url = feed_url
        self._apply_update = apply_update

    def run(self) -> None:
        result = check_and_update_xray_core(
            self._xray_path,
            self._channel,
            self._feed_url,
            apply_update=self._apply_update,
            on_progress=lambda d, t: self.progress.emit(int(d * 100 / t)),
        )
        self.done.emit(result)
