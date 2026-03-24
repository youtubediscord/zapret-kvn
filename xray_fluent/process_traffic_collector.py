from __future__ import annotations

import os
import urllib.request
import json
from dataclasses import dataclass
from typing import Any

from .constants import SINGBOX_CLASH_API_PORT

# Processes to hide (internal, not user traffic)
_HIDDEN_PROCESSES = {"xray.exe", "sing-box.exe", "tun2socks.exe"}


@dataclass(slots=True)
class ProcessTrafficSnapshot:
    exe: str            # "chrome.exe"
    upload: int         # bytes total (cumulative)
    download: int       # bytes total (cumulative)
    connections: int    # active connection count
    route: str          # "proxy" | "direct" | "mixed"


def collect_process_stats(clash_api_port: int = SINGBOX_CLASH_API_PORT) -> list[ProcessTrafficSnapshot]:
    """Poll sing-box Clash API and aggregate traffic by process.

    Returns list of ProcessTrafficSnapshot sorted by total traffic (desc).
    Returns empty list on error.
    """
    try:
        url = f"http://127.0.0.1:{clash_api_port}/connections"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data: dict[str, Any] = json.loads(resp.read())
    except Exception:
        return []

    connections = data.get("connections") or []

    # Aggregate by process exe name
    by_proc: dict[str, dict[str, Any]] = {}
    for conn in connections:
        meta = conn.get("metadata") or {}
        process_path = meta.get("processPath") or ""
        exe = os.path.basename(process_path).lower() if process_path else "unknown"

        # Skip hidden processes
        if exe in _HIDDEN_PROCESSES:
            continue

        if exe not in by_proc:
            by_proc[exe] = {"upload": 0, "download": 0, "conns": 0, "routes": set()}

        entry = by_proc[exe]
        entry["upload"] += conn.get("upload", 0)
        entry["download"] += conn.get("download", 0)
        entry["conns"] += 1

        # Determine route from chains
        chains = conn.get("chains") or []
        if chains:
            chain = chains[0].lower()
            if "proxy" in chain:
                entry["routes"].add("proxy")
            elif "direct" in chain:
                entry["routes"].add("direct")
            else:
                entry["routes"].add(chain)

    # Build snapshots
    result: list[ProcessTrafficSnapshot] = []
    for exe, stats in by_proc.items():
        routes = stats["routes"]
        if len(routes) > 1:
            route = "mixed"
        elif routes:
            route = next(iter(routes))
        else:
            route = "direct"

        # Use original case for display - find first match
        display_exe = exe  # lowercase fallback
        for conn in connections:
            meta = conn.get("metadata") or {}
            pp = meta.get("processPath") or ""
            if os.path.basename(pp).lower() == exe:
                display_exe = os.path.basename(pp)
                break

        result.append(ProcessTrafficSnapshot(
            exe=display_exe,
            upload=stats["upload"],
            download=stats["download"],
            connections=stats["conns"],
            route=route,
        ))

    # Sort by total traffic descending
    result.sort(key=lambda s: s.upload + s.download, reverse=True)
    return result
