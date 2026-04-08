from __future__ import annotations

import json
from pathlib import Path

from ..constants import (
    SINGBOX_DEFAULT_CONFIG_NAME,
    SINGBOX_TEMPLATES_DIR,
    XRAY_DEFAULT_CONFIG_NAME,
    XRAY_TEMPLATES_DIR,
)


def _read_default_template_text(base_dir: Path, default_name: str, *, label: str) -> str:
    path = (base_dir / default_name).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Не найден шаблон {label}: {path}")
    return path.read_text(encoding="utf-8")


def normalize_relative_json_path(value: str | Path | None, default_name: str) -> str:
    raw = str(value or "").strip().replace("\\", "/")
    if not raw:
        return default_name

    parts = [part for part in Path(raw).parts if part not in ("", ".", "..", "/")]
    relative = Path(*parts) if parts else Path(default_name)
    if not relative.suffix:
        relative = relative.with_suffix(".json")
    return relative.as_posix()


def resolve_profile_path(
    base_dir: Path,
    value: str | Path | None,
    default_name: str,
    *,
    label: str,
) -> Path:
    base_dir = base_dir.resolve()
    normalized = normalize_relative_json_path(value, default_name)
    if value is None or not str(value).strip():
        resolved = (base_dir / normalized).resolve()
    else:
        candidate = Path(value)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (base_dir / normalized).resolve()

    if not resolved.suffix:
        resolved = resolved.with_suffix(".json")

    try:
        resolved.relative_to(base_dir)
    except ValueError as exc:
        raise ValueError(f"Файл {label} должен находиться в {base_dir.as_posix()}/") from exc
    return resolved


def default_singbox_config_text() -> str:
    return _read_default_template_text(SINGBOX_TEMPLATES_DIR, SINGBOX_DEFAULT_CONFIG_NAME, label="sing-box")


def default_xray_config_text(
    *,
    proxy_host: str,
    socks_port: int,
    http_port: int,
    api_port: int,
) -> str:
    return _read_default_template_text(XRAY_TEMPLATES_DIR, XRAY_DEFAULT_CONFIG_NAME, label="xray")


def format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
    lines = text.splitlines()
    line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
    caret = ""
    if line:
        caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
    return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()


def validate_json_text(text: str) -> tuple[bool, str]:
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return False, format_json_error_message(text, exc)
    return True, "JSON корректен."
