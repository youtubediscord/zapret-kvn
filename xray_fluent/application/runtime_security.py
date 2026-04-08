from __future__ import annotations

import secrets
import string
from typing import Any


_PROXY_INBOUND_TYPES = {"socks", "http", "mixed"}


def generate_local_proxy_credentials(*, prefix: str = "local", password_length: int = 24) -> tuple[str, str]:
    suffix = secrets.token_hex(3)
    username = f"{prefix}-{suffix}"
    alphabet = string.ascii_letters + string.digits
    password = "".join(secrets.choice(alphabet) for _ in range(password_length))
    return username, password


def strip_xray_proxy_inbounds(payload: dict[str, Any], *, keep_tags: set[str] | None = None) -> int:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return 0

    keep = {str(tag).strip() for tag in (keep_tags or set()) if str(tag).strip()}
    filtered: list[Any] = []
    removed = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            filtered.append(inbound)
            continue
        tag = str(inbound.get("tag") or "").strip()
        protocol = str(inbound.get("protocol") or "").strip().lower()
        if tag in keep or protocol not in _PROXY_INBOUND_TYPES:
            filtered.append(inbound)
            continue
        removed += 1

    if removed:
        payload["inbounds"] = filtered
    return removed


def strip_singbox_proxy_inbounds(payload: dict[str, Any], *, keep_tags: set[str] | None = None) -> int:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return 0

    keep = {str(tag).strip() for tag in (keep_tags or set()) if str(tag).strip()}
    filtered: list[Any] = []
    removed = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            filtered.append(inbound)
            continue
        tag = str(inbound.get("tag") or "").strip()
        inbound_type = str(inbound.get("type") or inbound.get("protocol") or "").strip().lower()
        if tag in keep or inbound_type not in _PROXY_INBOUND_TYPES:
            filtered.append(inbound)
            continue
        removed += 1

    if removed:
        payload["inbounds"] = filtered
    return removed


def set_xray_socks_inbound_auth(
    payload: dict[str, Any],
    *,
    username: str,
    password: str,
    tag: str | None = None,
) -> bool:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return False

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol") or "").strip().lower() != "socks":
            continue
        inbound_tag = str(inbound.get("tag") or "").strip()
        if tag is not None and inbound_tag != tag:
            continue
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            settings = {}
            inbound["settings"] = settings
        settings["auth"] = "password"
        settings["accounts"] = [{"user": username, "pass": password}]
        return True
    return False
