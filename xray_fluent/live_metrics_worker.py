from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any
from urllib.request import Request

from .http_utils import urlopen

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import XRAY_PATH_DEFAULT
from .path_utils import resolve_configured_path
from .ping_worker import tcp_ping
from .process_traffic_collector import collect_process_stats, ProcessTrafficSnapshot


class LiveMetricsWorker(QThread):
    metrics = pyqtSignal(object)

    def __init__(
        self,
        xray_path: str,
        api_port: int,
        ping_host: str = "",
        ping_port: int = 0,
        interval_ms: int = 1000,
        ping_interval_sec: float = 3.0,
        mode: str = "xray",
        clash_api_port: int = 19090,
    ):
        super().__init__()
        self._xray_path = xray_path
        self._api_port = api_port
        self._ping_host = ping_host
        self._ping_port = ping_port
        self._interval_ms = max(250, interval_ms)
        self._ping_interval_sec = max(1.0, ping_interval_sec)
        self._stopped = False
        self._last_ping_ms: int | None = None
        self._mode = mode
        self._clash_api_port = clash_api_port

    def stop(self) -> None:
        self._stopped = True

    def run(self) -> None:
        prev_uplink: int | None = None
        prev_downlink: int | None = None
        prev_ts: float | None = None
        last_ping_ts = 0.0
        iteration_count = 0

        while not self._stopped:
            now = time.perf_counter()
            uplink_total, downlink_total = self._query_inbound_totals()

            down_bps = 0.0
            up_bps = 0.0
            if (
                uplink_total is not None
                and downlink_total is not None
                and prev_uplink is not None
                and prev_downlink is not None
                and prev_ts is not None
            ):
                dt = max(0.001, now - prev_ts)
                up_bps = max(0.0, (uplink_total - prev_uplink) / dt)
                down_bps = max(0.0, (downlink_total - prev_downlink) / dt)

            if uplink_total is not None and downlink_total is not None:
                prev_uplink = uplink_total
                prev_downlink = downlink_total
                prev_ts = now

            if self._ping_host and self._ping_port > 0 and (now - last_ping_ts) >= self._ping_interval_sec:
                self._last_ping_ms = tcp_ping(self._ping_host, self._ping_port, timeout=1.6)
                last_ping_ts = now

            process_stats = None
            if self._mode == "singbox" and iteration_count % 2 == 0:
                process_stats = collect_process_stats(self._clash_api_port)

            self.metrics.emit(
                {
                    "down_bps": down_bps,
                    "up_bps": up_bps,
                    "latency_ms": self._last_ping_ms,
                    "process_stats": process_stats,
                }
            )

            iteration_count += 1
            slept = 0
            while slept < self._interval_ms and not self._stopped:
                self.msleep(100)
                slept += 100

    def _query_inbound_totals(self) -> tuple[int | None, int | None]:
        if self._mode == "singbox":
            return self._query_clash_api_totals()
        return self._query_xray_stats()

    def _query_clash_api_totals(self) -> tuple[int | None, int | None]:
        try:
            req = Request(f"http://127.0.0.1:{self._clash_api_port}/connections")
            with urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
            upload = int(data.get("uploadTotal") or 0)
            download = int(data.get("downloadTotal") or 0)
            return upload, download
        except Exception:
            return None, None

    def _query_xray_stats(self) -> tuple[int | None, int | None]:
        exe = resolve_configured_path(
            self._xray_path,
            default_path=XRAY_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        if exe is None:
            return None, None
        if not exe.exists():
            return None, None

        try:
            result = subprocess.run(
                [str(exe), "api", "statsquery", f"--server=127.0.0.1:{self._api_port}"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return None, None

        if result.returncode != 0:
            return None, None

        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return None, None

        uplink = 0
        downlink = 0

        for stat in payload.get("stat", []):
            if not isinstance(stat, dict):
                continue
            name = str(stat.get("name") or "")
            value_raw = stat.get("value")
            try:
                value = int(value_raw or 0)
            except (TypeError, ValueError):
                value = 0

            if name in {
                "inbound>>>socks-in>>>traffic>>>uplink",
                "inbound>>>http-in>>>traffic>>>uplink",
            }:
                uplink += value
            elif name in {
                "inbound>>>socks-in>>>traffic>>>downlink",
                "inbound>>>http-in>>>traffic>>>downlink",
            }:
                downlink += value

        return uplink, downlink
