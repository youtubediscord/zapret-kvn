"""Per-process proxy usage monitor via Windows API.

Uses GetExtendedTcpTable to find which processes have connections
to xray SOCKS/HTTP ports, and GetPerTcpConnectionEStats for actual
per-connection byte counts (DataBytesIn/DataBytesOut).
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
from dataclasses import dataclass

# TCP_TABLE_OWNER_PID_CONNECTIONS = 4
_TCP_TABLE_OWNER_PID_CONN = 4
_AF_INET = 2
_MIB_TCP_STATE_ESTAB = 5

# TcpConnectionEstatsData = 1
_TCP_ESTATS_DATA = 1

_iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
_kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


class _MIB_TCPROW(ctypes.Structure):
    """Plain MIB_TCPROW (without PID) — required by GetPerTcpConnectionEStats."""
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
    ]


class _MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.wintypes.DWORD),
        ("table", _MIB_TCPROW_OWNER_PID * 1),
    ]


class _TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    """BOOLEAN EnableCollection — must be c_ubyte (1 byte), not BOOL (4 bytes)."""
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class _TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    """Per-connection byte counters. Size must be exactly 96 bytes.

    Fields after SegsIn are ULONG (4 bytes), not ULONG64 (8 bytes).
    ctypes handles alignment padding automatically.
    """
    _fields_ = [
        ("DataBytesOut", ctypes.c_uint64),
        ("DataSegsOut", ctypes.c_uint64),
        ("DataBytesIn", ctypes.c_uint64),
        ("DataSegsIn", ctypes.c_uint64),
        ("SegsOut", ctypes.c_uint64),
        ("SegsIn", ctypes.c_uint64),
        ("SoftErrors", ctypes.c_ulong),
        ("SoftErrorReason", ctypes.c_ulong),
        ("SndUna", ctypes.c_ulong),
        ("SndNxt", ctypes.c_ulong),
        ("SndMax", ctypes.c_ulong),
        ("ThruBytesAcked", ctypes.c_uint64),
        ("RcvNxt", ctypes.c_ulong),
        ("ThruBytesReceived", ctypes.c_uint64),
    ]


# Cache PID → exe name (PIDs don't change often)
_pid_cache: dict[int, str] = {}

# Track connections with estats already enabled — avoid redundant Set calls
_estats_enabled: set[tuple[int, int, int, int]] = set()  # (localAddr, localPort, remoteAddr, remotePort)


def _pid_to_exe(pid: int) -> str:
    """Get exe name from PID. Cached."""
    if pid in _pid_cache:
        return _pid_cache[pid]
    try:
        h = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(260)
            size = ctypes.wintypes.DWORD(260)
            if _kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                exe = os.path.basename(buf.value)
                _pid_cache[pid] = exe
                return exe
        finally:
            _kernel32.CloseHandle(h)
    except Exception:
        pass
    return ""


def _ntohs(port: int) -> int:
    """Network byte order to host byte order for port."""
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


def _make_tcprow(row: _MIB_TCPROW_OWNER_PID) -> _MIB_TCPROW:
    return _MIB_TCPROW(
        dwState=row.dwState, dwLocalAddr=row.dwLocalAddr,
        dwLocalPort=row.dwLocalPort, dwRemoteAddr=row.dwRemoteAddr,
        dwRemotePort=row.dwRemotePort,
    )


def _conn_key(row: _MIB_TCPROW_OWNER_PID) -> tuple[int, int, int, int]:
    return (row.dwLocalAddr, row.dwLocalPort, row.dwRemoteAddr, row.dwRemotePort)


def _enable_estats(row: _MIB_TCPROW_OWNER_PID) -> bool:
    """Enable per-connection byte tracking. Requires admin. Idempotent."""
    key = _conn_key(row)
    if key in _estats_enabled:
        return True
    tcp_row = _make_tcprow(row)
    rw = _TCP_ESTATS_DATA_RW_v0(EnableCollection=1)
    ret = _iphlpapi.SetPerTcpConnectionEStats(
        ctypes.byref(tcp_row), _TCP_ESTATS_DATA,
        ctypes.byref(rw), 0, ctypes.sizeof(rw), 0,
    )
    if ret == 0:
        _estats_enabled.add(key)
        return True
    return False


def _get_estats_bytes(row: _MIB_TCPROW_OWNER_PID) -> tuple[int, int] | None:
    """Get (DataBytesIn, DataBytesOut) for a TCP connection.

    Returns None if the API call fails (connection closed, access denied, etc.).
    """
    tcp_row = _make_tcprow(row)
    rod = _TCP_ESTATS_DATA_ROD_v0()
    ret = _iphlpapi.GetPerTcpConnectionEStats(
        ctypes.byref(tcp_row), _TCP_ESTATS_DATA,
        None, 0, 0,
        None, 0, 0,
        ctypes.byref(rod), 0, ctypes.sizeof(rod),
    )
    if ret == 0:
        return rod.DataBytesIn, rod.DataBytesOut
    return None


@dataclass(slots=True)
class ProxyProcessInfo:
    exe: str
    connections: int
    pids: set[int]
    bytes_in: int = 0   # actual TCP bytes received (download)
    bytes_out: int = 0  # actual TCP bytes sent (upload)


def get_proxy_connections(socks_port: int = 1390, http_port: int = 1391) -> list[ProxyProcessInfo]:
    """Find processes connected to xray proxy ports with per-connection byte counts.

    Uses GetExtendedTcpTable for connection/PID discovery and
    GetPerTcpConnectionEStats for actual network bytes per connection.
    Requires Administrator for byte counts; falls back to 0 without admin.
    """
    target_ports = {socks_port, http_port}
    localhost = 0x0100007F  # 127.0.0.1 in network byte order

    size = ctypes.wintypes.DWORD(0)
    _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_CONN, 0)

    buf = (ctypes.c_byte * size.value)()
    ret = _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, _AF_INET, _TCP_TABLE_OWNER_PID_CONN, 0)
    if ret != 0:
        return []

    table = ctypes.cast(buf, ctypes.POINTER(_MIB_TCPTABLE_OWNER_PID)).contents
    n = table.dwNumEntries

    row_array = ctypes.cast(
        ctypes.byref(table.table),
        ctypes.POINTER(_MIB_TCPROW_OWNER_PID * n),
    ).contents

    by_exe: dict[str, ProxyProcessInfo] = {}
    for i in range(n):
        row = row_array[i]
        if row.dwState != _MIB_TCP_STATE_ESTAB:
            continue
        remote_port = _ntohs(row.dwRemotePort)
        if remote_port not in target_ports:
            continue
        if row.dwRemoteAddr != localhost:
            continue

        pid = row.dwOwningPid
        exe = _pid_to_exe(pid)
        if not exe or exe.lower() in ("xray.exe", "sing-box.exe"):
            continue

        _enable_estats(row)
        estats = _get_estats_bytes(row)

        if exe not in by_exe:
            by_exe[exe] = ProxyProcessInfo(exe=exe, connections=0, pids=set())
        by_exe[exe].connections += 1
        by_exe[exe].pids.add(pid)
        if estats is not None:
            by_exe[exe].bytes_in += estats[0]
            by_exe[exe].bytes_out += estats[1]

    result = sorted(by_exe.values(), key=lambda p: p.connections, reverse=True)
    return result


def clear_pid_cache() -> None:
    """Clear PID→exe cache and estats tracking. Call on disconnect."""
    _pid_cache.clear()
    _estats_enabled.clear()
