from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from .constants import DATA_DIR


TRAFFIC_HISTORY_FILE = DATA_DIR / "traffic_history.json"

_MAX_REASONABLE_BYTES_PER_SECOND = 2 * 1024 * 1024 * 1024  # 2 GiB/s
_MIN_REASONABLE_SESSION_BYTES = 2 * 1024 * 1024 * 1024 * 1024  # 2 TiB
_HARD_REASONABLE_SESSION_BYTES = 1024 * 1024 * 1024 * 1024 * 1024  # 1 PiB


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
        except Exception:
            return

        changed = False
        raw_sessions = data.get("sessions") if isinstance(data, dict) else []
        if not isinstance(raw_sessions, list):
            raw_sessions = []
            changed = True

        sessions: list[TrafficSession] = []
        for item in raw_sessions:
            if not isinstance(item, dict):
                changed = True
                continue
            try:
                session = TrafficSession.from_dict(item)
            except Exception:
                changed = True
                continue
            if self._sanitize_session(session):
                changed = True
            sessions.append(session)
        self._sessions = sessions

        raw_daily = data.get("daily_totals") if isinstance(data, dict) else {}
        if not isinstance(raw_daily, dict):
            raw_daily = {}
            changed = True

        rebuilt_daily = self._build_daily_totals_from_sessions(self._sessions)
        if rebuilt_daily != raw_daily:
            changed = True
        self._daily_totals = rebuilt_daily

        if changed:
            self._save()

    def _save(self) -> None:
        TRAFFIC_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "sessions": [s.to_dict() for s in self._sessions],
            "daily_totals": self._daily_totals,
        }
        TRAFFIC_HISTORY_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def start_session(self, node_name: str, mode: str) -> str:
        if self._current_session is not None:
            self.end_session()
        session = TrafficSession(
            started_at=datetime.now(timezone.utc).isoformat(),
            node_name=node_name,
            mode=mode,
        )
        self._current_session = session
        self._sessions.append(session)
        self._cleanup_old_sessions()
        self._save()
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
        self._sanitize_session(s)

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value)
        except Exception:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _sanitize_counter(value: int) -> int:
        try:
            as_int = int(value)
        except Exception:
            return 0
        return as_int if as_int > 0 else 0

    def _session_duration_seconds(self, started_at: str, ended_at: str | None) -> int:
        start_dt = self._parse_iso_datetime(started_at)
        if start_dt is None:
            return 0
        end_dt = self._parse_iso_datetime(ended_at) if ended_at else datetime.now(timezone.utc)
        if end_dt is None:
            end_dt = datetime.now(timezone.utc)
        if end_dt <= start_dt:
            return 0
        return int((end_dt - start_dt).total_seconds())

    def _session_limit_bytes(self, started_at: str, ended_at: str | None) -> int:
        duration_sec = self._session_duration_seconds(started_at, ended_at)
        if duration_sec <= 0:
            return _MIN_REASONABLE_SESSION_BYTES
        dynamic_limit = duration_sec * _MAX_REASONABLE_BYTES_PER_SECOND
        bounded_limit = min(_HARD_REASONABLE_SESSION_BYTES, dynamic_limit)
        return max(_MIN_REASONABLE_SESSION_BYTES, bounded_limit)

    def _sanitize_session(self, session: TrafficSession) -> bool:
        changed = False
        limit = self._session_limit_bytes(session.started_at, session.ended_at)

        total_up = self._sanitize_counter(session.total_upload)
        total_down = self._sanitize_counter(session.total_download)

        if session.processes:
            summed_up = 0
            summed_down = 0
            for entry in session.processes.values():
                entry_up = self._sanitize_counter(entry.upload)
                entry_down = self._sanitize_counter(entry.download)

                if entry_up > limit:
                    entry_up = 0
                if entry_down > limit:
                    entry_down = 0

                if entry_up != entry.upload:
                    entry.upload = entry_up
                    changed = True
                if entry_down != entry.download:
                    entry.download = entry_down
                    changed = True

                summed_up += entry_up
                summed_down += entry_down

            total_up = summed_up
            total_down = summed_down

        if total_up > limit:
            total_up = 0
        if total_down > limit:
            total_down = 0

        if total_up != session.total_upload:
            session.total_upload = total_up
            changed = True
        if total_down != session.total_download:
            session.total_download = total_down
            changed = True
        return changed

    def _build_daily_totals_from_sessions(self, sessions: list[TrafficSession]) -> dict[str, dict[str, int]]:
        totals: dict[str, dict[str, int]] = {}
        for session in sessions:
            day_key = self._session_day_key(session.started_at)
            if not day_key:
                continue
            daily = totals.setdefault(day_key, {"upload": 0, "download": 0})
            daily["upload"] += session.total_upload
            daily["download"] += session.total_download
        return totals

    def _session_day_key(self, started_at: str) -> str:
        dt = self._parse_iso_datetime(started_at)
        if dt is not None:
            return dt.strftime("%Y-%m-%d")
        if len(started_at) >= 10 and started_at[4:5] == "-" and started_at[7:8] == "-":
            return started_at[:10]
        return ""


    def end_session(self) -> None:
        if self._current_session:
            # Accumulate session totals into daily totals
            day_key = self._session_day_key(self._current_session.started_at)
            if not day_key:
                day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            daily = self._daily_totals.get(day_key)
            if daily is None:
                daily = {"upload": 0, "download": 0}
                self._daily_totals[day_key] = daily
            daily["upload"] += self._current_session.total_upload
            daily["download"] += self._current_session.total_download

            self._current_session.ended_at = datetime.now(timezone.utc).isoformat()
            self._current_session = None
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
