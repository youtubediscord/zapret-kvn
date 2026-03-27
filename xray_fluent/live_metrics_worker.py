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
from .subprocess_utils import decode_output, run_text
from .win_proc_monitor import get_proxy_connections, ProxyProcessInfo


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
        socks_port: int = 10808,
        http_port: int = 10809,
        xray_inbound_tags: list[str] | None = None,
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
        self._socks_port = socks_port
        self._http_port = http_port
        normalized_inbound_tags: list[str] = []
        for tag in xray_inbound_tags or []:
            clean = str(tag).strip()
            if clean and clean not in normalized_inbound_tags:
                normalized_inbound_tags.append(clean)
        self._xray_inbound_tags = tuple(normalized_inbound_tags)

    def stop(self) -> None:
        self._stopped = True

    def run(self) -> None:
        prev_uplink: int | None = None
        prev_downlink: int | None = None
        prev_ts: float | None = None
        last_ping_ts = 0.0
        iteration_count = 0

        # Proxy mode: per-process traffic via TCP connection estats
        proxy_prev_bytes: dict[str, tuple[int, int]] = {}  # {exe: (in, out)} for speed & drop detection
        proxy_closed_bytes: dict[str, tuple[int, int]] = {}  # {exe: (in, out)} accumulated from closed conns

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
            if iteration_count % 2 == 0:
                if self._mode == "singbox":
                    process_stats = collect_process_stats(self._clash_api_port)
                elif self._mode == "xray":
                    process_stats = self._collect_proxy_process_stats(
                        proxy_prev_bytes, proxy_closed_bytes,
                    )

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

    def _collect_proxy_process_stats(
        self,
        prev_bytes: dict[str, tuple[int, int]],
        closed_bytes: dict[str, tuple[int, int]],
    ) -> list[ProcessTrafficSnapshot] | None:
        """Build per-process stats in proxy mode.

        Uses GetPerTcpConnectionEStats for actual per-connection byte counts.
        Tracks closed connections: when active bytes drop, the lost bytes
        are accumulated in closed_bytes so "Всего" grows monotonically.
        """
        try:
            proxy_procs = get_proxy_connections(self._socks_port, self._http_port)
        except Exception:
            return None
        if not proxy_procs:
            return None

        result: list[ProcessTrafficSnapshot] = []
        for p in proxy_procs:
            prev_in, prev_out = prev_bytes.get(p.exe, (0, 0))
            cl_in, cl_out = closed_bytes.get(p.exe, (0, 0))

            # Detect closed connections: active bytes dropped (but not to zero — that indicates API glitch)
            if p.bytes_in < prev_in and p.bytes_in > 0:
                cl_in += prev_in - p.bytes_in
            if p.bytes_out < prev_out and p.bytes_out > 0:
                cl_out += prev_out - p.bytes_out
            closed_bytes[p.exe] = (cl_in, cl_out)

            # Total = accumulated from closed conns + current active conns
            total_in = cl_in + p.bytes_in
            total_out = cl_out + p.bytes_out

            # Speed from active connection deltas
            down_speed = max(0.0, (p.bytes_in - prev_in) / 2.0) if prev_in > 0 and p.bytes_in >= prev_in else 0.0
            up_speed = max(0.0, (p.bytes_out - prev_out) / 2.0) if prev_out > 0 and p.bytes_out >= prev_out else 0.0
            prev_bytes[p.exe] = (p.bytes_in, p.bytes_out)

            result.append(ProcessTrafficSnapshot(
                exe=p.exe,
                upload=total_out,
                download=total_in,
                connections=p.connections,
                route="proxy",
                proxy_bytes=total_in + total_out,
                down_speed=down_speed,
                up_speed=up_speed,
            ))

        result.sort(key=lambda s: s.upload + s.download, reverse=True)
        return result

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
        if self._api_port <= 0:
            return None, None
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
            result = run_text(
                [str(exe), "api", "statsquery", f"--server=127.0.0.1:{self._api_port}"],
                timeout=2,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception:
            return None, None

        if result.returncode != 0:
            return None, None

        try:
            payload = json.loads(decode_output(result.stdout) or "{}")
        except json.JSONDecodeError:
            return None, None

        uplink = 0
        downlink = 0
        inbound_uplink_stats = {f"inbound>>>{tag}>>>traffic>>>uplink" for tag in self._xray_inbound_tags}
        inbound_downlink_stats = {f"inbound>>>{tag}>>>traffic>>>downlink" for tag in self._xray_inbound_tags}

        for stat in payload.get("stat", []):
            if not isinstance(stat, dict):
                continue
            name = str(stat.get("name") or "")
            value_raw = stat.get("value")
            try:
                value = int(value_raw or 0)
            except (TypeError, ValueError):
                value = 0

            if name in inbound_uplink_stats:
                uplink += value
            elif name in inbound_downlink_stats:
                downlink += value

        return uplink, downlink
