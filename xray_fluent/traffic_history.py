from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .constants import DATA_DIR


TRAFFIC_HISTORY_FILE = DATA_DIR / "traffic_history.json"


@dataclass
class ProcessTrafficEntry:
    upload: int = 0
    download: int = 0
    route: str = "direct"  # "proxy" | "direct" | "mixed"

    def to_dict(self) -> dict[str, Any]:
        return {"upload": self.upload, "download": self.download, "route": self.route}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ProcessTrafficEntry:
        return ProcessTrafficEntry(
            upload=int(data.get("upload", 0)),
            download=int(data.get("download", 0)),
            route=str(data.get("route", "direct")),
        )


@dataclass
class TrafficSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = ""
    ended_at: str | None = None
    node_name: str = ""
    mode: str = ""
    total_upload: int = 0
    total_download: int = 0
    processes: dict[str, ProcessTrafficEntry] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "node_name": self.node_name,
            "mode": self.mode,
            "total_upload": self.total_upload,
            "total_download": self.total_download,
            "processes": {k: v.to_dict() for k, v in self.processes.items()},
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> TrafficSession:
        procs = {}
        for k, v in (data.get("processes") or {}).items():
            procs[k] = ProcessTrafficEntry.from_dict(v) if isinstance(v, dict) else ProcessTrafficEntry()
        return TrafficSession(
            id=str(data.get("id") or uuid.uuid4()),
            started_at=str(data.get("started_at", "")),
            ended_at=data.get("ended_at"),
            node_name=str(data.get("node_name", "")),
            mode=str(data.get("mode", "")),
            total_upload=int(data.get("total_upload", 0)),
            total_download=int(data.get("total_download", 0)),
            processes=procs,
        )


class TrafficHistoryStorage:
    def __init__(self) -> None:
        self._sessions: list[TrafficSession] = []
        self._daily_totals: dict[str, dict[str, int]] = {}  # {"2026-03-24": {"upload": N, "download": N}}
        self._current_session: TrafficSession | None = None
        self._load()

    def _load(self) -> None:
        if not TRAFFIC_HISTORY_FILE.exists():
            return
        try:
            data = json.loads(TRAFFIC_HISTORY_FILE.read_text(encoding="utf-8"))
            self._sessions = [TrafficSession.from_dict(s) for s in (data.get("sessions") or [])]
            self._daily_totals = dict(data.get("daily_totals") or {})
        except Exception:
            pass

    def _save(self) -> None:
        TRAFFIC_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "sessions": [s.to_dict() for s in self._sessions],
            "daily_totals": self._daily_totals,
        }
        TRAFFIC_HISTORY_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def start_session(self, node_name: str, mode: str) -> str:
        session = TrafficSession(
            started_at=datetime.now(timezone.utc).isoformat(),
            node_name=node_name,
            mode=mode,
        )
        self._current_session = session
        self._sessions.append(session)
        return session.id

    def update_session(self, process_stats: dict[str, tuple[int, int, str]]) -> None:
        """Update current session with process traffic data.

        Args:
            process_stats: {exe_name: (upload_bytes, download_bytes, route)}
        """
        s = self._current_session
        if not s:
            return

        total_up = 0
        total_down = 0
        for exe, (up, down, route) in process_stats.items():
            entry = s.processes.get(exe)
            if entry is None:
                entry = ProcessTrafficEntry(route=route)
                s.processes[exe] = entry
            entry.upload = up
            entry.download = down
            if entry.route != route and route != entry.route:
                entry.route = "mixed" if entry.route != "mixed" else entry.route
            total_up += up
            total_down += down

        s.total_upload = total_up
        s.total_download = total_down

        # Update daily totals
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily = self._daily_totals.get(today)
        if daily is None:
            daily = {"upload": 0, "download": 0}
            self._daily_totals[today] = daily
        daily["upload"] = max(daily["upload"], total_up)
        daily["download"] = max(daily["download"], total_down)

    def end_session(self) -> None:
        if self._current_session:
            self._current_session.ended_at = datetime.now(timezone.utc).isoformat()
            self._current_session = None
            self._cleanup_old_sessions()
            self._save()

    def save_periodic(self) -> None:
        """Called periodically (every 30s) to persist current state."""
        if self._current_session:
            self._save()

    def get_sessions(self, days: int = 30) -> list[TrafficSession]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return [s for s in self._sessions if s.started_at >= cutoff]

    def get_daily_totals(self, days: int = 30) -> dict[str, dict[str, int]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        return {k: v for k, v in self._daily_totals.items() if k >= cutoff}

    def get_process_totals(self, days: int = 30) -> dict[str, dict[str, int | str]]:
        """Aggregate process traffic across sessions for the given period."""
        sessions = self.get_sessions(days)
        totals: dict[str, dict[str, Any]] = {}
        for s in sessions:
            for exe, entry in s.processes.items():
                if exe not in totals:
                    totals[exe] = {"upload": 0, "download": 0, "route": entry.route}
                totals[exe]["upload"] += entry.upload
                totals[exe]["download"] += entry.download
        return totals

    @property
    def current_session(self) -> TrafficSession | None:
        return self._current_session

    def _cleanup_old_sessions(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        self._sessions = [s for s in self._sessions if s.started_at >= cutoff]
        cutoff_day = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%d")
        self._daily_totals = {k: v for k, v in self._daily_totals.items() if k >= cutoff_day}
