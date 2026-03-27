from __future__ import annotations

import os
from typing import Any

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

from PyQt6.QtCore import QObject, QProcess, pyqtSignal

from .constants import BASE_DIR
from .subprocess_utils import (
    decode_output,
    kill_processes_by_path,
    result_output_text,
    run_text_pumped,
    sleep_with_events,
    wait_for_qprocess_finished,
    wait_for_qprocess_ready_read,
    wait_for_qprocess_started,
)

TUN2SOCKS_PATH_DEFAULT = BASE_DIR / "core" / "tun2socks.exe"
TUN_DEVICE_NAME = "ZapretKVN_TUN"
TUN_GW = "172.19.0.1"
TUN_ADDR = "172.19.0.2"
TUN_MASK = "255.255.255.252"
TUN_GW6 = "fd00::1"
TUN_CIDR = "172.19.0.1/30"


class Tun2SocksManager(QObject):
    started = pyqtSignal()
    stopped = pyqtSignal(int)
    log_received = pyqtSignal(str)
    error = pyqtSignal(str)
    state_changed = pyqtSignal(bool)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_ready_read)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)
        self._running = False
        self._stop_requested = False
        self._server_ip: str = ""
        self._orig_gateway: str = ""
        self._tun_idx: str = ""
        self._helper_routes: list[list[str]] = []

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, socks_port: int, server_ip: str = "") -> bool:
        exe = TUN2SOCKS_PATH_DEFAULT
        if not exe.is_file():
            self.error.emit(f"tun2socks.exe not found: {exe}")
            return False

        self._server_ip = server_ip

        if self._process.state() != QProcess.ProcessState.NotRunning:
            if not self.stop(expected=True):
                self.error.emit("failed to stop previous tun2socks process")
                return False
        elif self._running:
            self._running = False
            self.state_changed.emit(False)

        # Kill orphaned tun2socks
        self._kill_orphaned()

        self._process.setProgram(str(exe))
        self._process.setArguments([
            "-device", f"tun://{TUN_DEVICE_NAME}",
            "-proxy", f"socks5://127.0.0.1:{socks_port}",
            "-loglevel", "error",
        ])
        self._process.start()

        if not wait_for_qprocess_started(self._process, 5000):
            self.error.emit(f"failed to start tun2socks: {self._process.errorString()}")
            return False

        # Wait for TUN adapter to be created
        wait_for_qprocess_ready_read(self._process, 3000)
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self.error.emit("tun2socks exited right after start")
            return False

        # Wait until TUN interface appears (up to 10 seconds)
        for _ in range(20):
            result = run_text_pumped(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            if TUN_DEVICE_NAME in result_output_text(result):
                break
            sleep_with_events(0.5)
        else:
            self._process.terminate()
            wait_for_qprocess_finished(self._process, 2000)
            self.error.emit("TUN adapter did not appear after tun2socks start")
            return False

        # Configure routes
        if not self._setup_routes():
            self.stop(expected=True)
            return False
        return True

    def stop(self, expected: bool = True) -> bool:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._stop_requested = False
            if self._running:
                self._running = False
                self.state_changed.emit(False)
            return True

        self._stop_requested = expected
        self._process.terminate()
        if wait_for_qprocess_finished(self._process, 2000):
            self._cleanup_routes()
            return True

        self._process.kill()
        if wait_for_qprocess_finished(self._process, 1000):
            self._cleanup_routes()
            return True

        if self._process.state() == QProcess.ProcessState.NotRunning:
            self._cleanup_routes()
            return True

        self._stop_requested = False
        self.error.emit("failed to stop tun2socks in time")
        return False

    def _setup_routes(self) -> bool:
        """Set up routes so all traffic goes through the TUN adapter."""
        if os.name != "nt":
            return True
        try:
            self._helper_routes = []
            # Find TUN interface index by name
            result = run_text_pumped(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            tun_idx = ""
            for line in result_output_text(result).splitlines():
                if TUN_DEVICE_NAME in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        tun_idx = parts[0]
                        break
            if not tun_idx:
                self.error.emit("failed to detect TUN interface index")
                return False

            # Get current default gateway
            result = run_text_pumped(
                ["cmd", "/c", "route", "print", "0.0.0.0"],
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            orig_gw = ""
            for line in result_output_text(result).splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    orig_gw = parts[2]
                    break
            if not orig_gw:
                self.error.emit("failed to detect current default gateway")
                return False
            self._orig_gateway = orig_gw
            self._tun_idx = tun_idx

            # Set TUN interface metric very low so it wins
            run_text_pumped(
                ["netsh", "interface", "ipv4", "set", "interface", tun_idx, "metric=1"],
                timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )

            cmds: list[list[str]] = []
            if self._server_ip:
                cmds.append(["route", "add", self._server_ip, "mask", "255.255.255.255", orig_gw, "metric", "1"])
            helper_routes = [
                [orig_gw, "255.255.255.255"],
                ["192.168.0.0", "255.255.0.0"],
                ["10.0.0.0", "255.0.0.0"],
                ["172.16.0.0", "255.240.0.0"],
                ["169.254.0.0", "255.255.0.0"],
            ]
            for destination, mask in helper_routes:
                cmd = ["route", "add", destination, "mask", mask, orig_gw, "metric", "1"]
                cmds.append(cmd)
                self._helper_routes.append([destination, mask, orig_gw])

            cleanup_cmds = [
                ["route", "delete", "0.0.0.0", "mask", "128.0.0.0", TUN_GW],
                ["route", "delete", "128.0.0.0", "mask", "128.0.0.0", TUN_GW],
                ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", f"interface={tun_idx}"],
                ["netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", f"interface={tun_idx}"],
                ["netsh", "interface", "ipv6", "delete", "route", "::/0", f"interface={tun_idx}"],
            ]
            if self._server_ip:
                cleanup_cmds.append(["route", "delete", self._server_ip])
            for destination, mask, gateway in self._helper_routes:
                cleanup_cmds.append(["route", "delete", destination, "mask", mask, gateway])
            for cmd in cleanup_cmds:
                run_text_pumped(cmd, timeout=5, creationflags=_CREATE_NO_WINDOW)

            # Use netsh to add TUN routes — this correctly sets interface metric
            cmds += [
                ["netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", f"interface={tun_idx}", f"nexthop={TUN_GW}", "metric=0"],
                ["netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", f"interface={tun_idx}", f"nexthop={TUN_GW}", "metric=0"],
                ["netsh", "interface", "ipv6", "add", "route", "::/0", f"interface={tun_idx}", "metric=1"],
            ]
            for cmd in cmds:
                r = run_text_pumped(cmd, timeout=5, creationflags=_CREATE_NO_WINDOW)
                self.log_received.emit(f"[tun2socks] {' '.join(cmd)} -> rc={r.returncode}")
                if r.returncode != 0:
                    details = result_output_text(r).strip()
                    if details:
                        self.log_received.emit(f"[tun2socks] command output: {details}")
                    self._cleanup_routes()
                    self.error.emit(f"failed to configure route: {' '.join(cmd)}")
                    return False
            return True
        except Exception as exc:
            self._cleanup_routes()
            self.log_received.emit(f"[tun2socks] route setup error: {exc}")
            return False

    def _cleanup_routes(self) -> None:
        """Remove routes added by _setup_routes."""
        if os.name != "nt":
            return
        try:
            cmds = [
                ["route", "delete", "0.0.0.0", "mask", "128.0.0.0", TUN_GW],
                ["route", "delete", "128.0.0.0", "mask", "128.0.0.0", TUN_GW],
            ]
            if hasattr(self, '_tun_idx') and self._tun_idx:
                cmds += [
                    ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", f"interface={self._tun_idx}"],
                    ["netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", f"interface={self._tun_idx}"],
                    ["netsh", "interface", "ipv6", "delete", "route", "::/0", f"interface={self._tun_idx}"],
                ]
            if self._server_ip:
                cmds.append(["route", "delete", self._server_ip])
            for destination, mask, gateway in self._helper_routes:
                cmds.append(["route", "delete", destination, "mask", mask, gateway])
            for cmd in cmds:
                run_text_pumped(cmd, timeout=5, creationflags=_CREATE_NO_WINDOW)
            self._helper_routes = []
        except Exception:
            pass

    @staticmethod
    def _kill_orphaned() -> None:
        if os.name != "nt":
            return
        try:
            if kill_processes_by_path("tun2socks.exe", TUN2SOCKS_PATH_DEFAULT, timeout=5):
                sleep_with_events(1.0)
        except Exception:
            pass

    def _on_ready_read(self) -> None:
        chunk = self._process.readAllStandardOutput()
        raw = getattr(chunk, "data")()
        if isinstance(raw, (bytes, bytearray)):
            text = decode_output(bytes(raw))
        else:
            text = str(raw)
        for line in text.splitlines():
            clean = line.rstrip()
            if clean:
                self.log_received.emit(clean)

    def _on_started(self) -> None:
        self._stop_requested = False
        self._running = True
        self.started.emit()
        self.state_changed.emit(True)

    def _on_error(self, process_error: QProcess.ProcessError) -> None:
        if self._stop_requested and process_error == QProcess.ProcessError.Crashed:
            return
        self.error.emit(f"tun2socks error: {process_error.name} ({self._process.errorString()})")

    def _on_finished(self, exit_code: int, _exit_status: int = 0) -> None:
        self._stop_requested = False
        self._running = False
        self._cleanup_routes()
        self.stopped.emit(exit_code)
        self.state_changed.emit(False)
