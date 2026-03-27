"""
Build XrayFluent portable exe via PyInstaller.

Usage:  python build.py          — full build (clean + compile + pack zip)
        python build.py --no-zip — skip zip creation
        python build.py --clean  — only wipe previous build artefacts

Requires .venv created by setup.bat (or manually).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
VENV_PIP = VENV_DIR / "Scripts" / "pip.exe"

APP_NAME = "ZapretKVN"

DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"
APP_DIR = DIST_DIR / APP_NAME
ZIP_PATH = DIST_DIR / f"{APP_NAME}-portable.zip"

MANIFEST = ROOT / "uac_admin.manifest"
CORE_DIR = ROOT / "core"
ZAPRET_DIR = ROOT / "zapret"
DATA_TEMPLATES_DIR = ROOT / "data" / "templates"


def _print(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def _run(cmd: list[str], **kwargs) -> None:
    _print(f"> {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def _copy_tree_merge(src: Path, dst: Path) -> None:
    """Copy src tree into dst, overwriting files where possible and skipping locked ones."""
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            _copy_tree_merge(item, target)
        else:
            try:
                shutil.copy2(str(item), str(target))
            except PermissionError:
                _print(f"  skipped (locked): {target.name}")


# ------------------------------------------------------------------
def ensure_venv() -> None:
    if VENV_PYTHON.exists():
        _print(f"venv OK: {VENV_PYTHON}")
        return
    _print("Creating virtual environment ...")
    _run([sys.executable, "-m", "venv", str(VENV_DIR)])
    _run([str(VENV_PIP), "install", "--upgrade", "pip"])
    _run([str(VENV_PIP), "install", "-r", str(ROOT / "requirements.txt")])


def clean() -> None:
    # build/ is purely temporary — safe to nuke
    if BUILD_DIR.exists():
        _print(f"Removing {BUILD_DIR}")
        try:
            shutil.rmtree(BUILD_DIR)
        except PermissionError:
            _print(f"ERROR: Cannot remove {BUILD_DIR} — is XrayFluent.exe still running?")
            _print("Close the app (tray -> Quit) and try again.")
            raise SystemExit(1)

    # dist/XrayFluent/ — remove everything EXCEPT data/, core/, zapret/
    # core/ and zapret/ are kept because running binaries (xray.exe) lock them;
    # they will be merged/overwritten in build_exe() instead.
    keep_dirs = {"data", "core", "zapret"}
    if APP_DIR.exists():
        for child in APP_DIR.iterdir():
            if child.name in keep_dirs:
                _print(f"Keeping {child}")
                continue
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except PermissionError:
                _print(f"WARNING: Cannot remove {child}, skipping")
        _print(f"Cleaned {APP_DIR} (data/, core/, zapret/ preserved)")


def build_exe() -> None:
    ensure_venv()

    # Build into a temporary directory so PyInstaller doesn't touch the live
    # APP_DIR (which may contain locked files like running xray.exe).
    temp_dist = DIST_DIR / "_build_tmp"
    if temp_dist.exists():
        shutil.rmtree(temp_dist)

    cmd = [
        str(VENV_PYTHON), "-m", "PyInstaller",
        str(ROOT / "main.py"),
        "--name", APP_NAME,
        "--noconfirm",
        "--clean",
        "--console",
        "--onedir",
        "--uac-admin",
        "--manifest", str(MANIFEST),
        "--distpath", str(temp_dist),
        # win32comext is needed by qframelesswindow for Mica/DWM effects
        "--hidden-import", "win32comext",
        "--hidden-import", "win32comext.shell",
        "--hidden-import", "win32comext.shell.shellcon",
        # encodings.idna is needed by socket.getaddrinfo() for hostname resolution
        "--hidden-import", "encodings.idna",
    ]
    _run(cmd, cwd=str(ROOT))

    # Merge PyInstaller output into the real APP_DIR (skip locked files)
    temp_app = temp_dist / APP_NAME
    _print(f"Merging build output -> {APP_DIR}")
    _copy_tree_merge(temp_app, APP_DIR)
    shutil.rmtree(temp_dist, ignore_errors=True)

    # Copy core/ into dist (merge, skip locked files like running xray.exe)
    dst_core = APP_DIR / "core"
    _print(f"Merging core -> {dst_core}")
    _copy_tree_merge(CORE_DIR, dst_core)

    # Copy zapret/ into dist (merge, skip locked files)
    dst_zapret = APP_DIR / "zapret"
    if ZAPRET_DIR.is_dir():
        _print(f"Merging zapret -> {dst_zapret}")
        _copy_tree_merge(ZAPRET_DIR, dst_zapret)

    # Copy tracked raw config templates for first-run users
    dst_templates = APP_DIR / "data" / "templates"
    if DATA_TEMPLATES_DIR.is_dir():
        _print(f"Merging templates -> {dst_templates}")
        _copy_tree_merge(DATA_TEMPLATES_DIR, dst_templates)

    _print(f"Build complete: {APP_DIR / (APP_NAME + '.exe')}")


def pack_zip() -> None:
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()
    _print(f"Creating {ZIP_PATH} ...")
    shutil.make_archive(str(ZIP_PATH.with_suffix("")), "zip", str(DIST_DIR), APP_NAME)
    _print(f"Portable archive ready: {ZIP_PATH}")


# ------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Build XrayFluent portable exe")
    parser.add_argument("--no-zip", action="store_true", help="skip zip creation")
    parser.add_argument("--clean", action="store_true", help="only clean build artefacts")
    args = parser.parse_args()

    os.chdir(ROOT)

    if args.clean:
        clean()
        _print("Done.")
        return 0

    clean()
    build_exe()

    if not args.no_zip:
        pack_zip()

    _print("All done!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
