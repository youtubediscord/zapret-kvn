from __future__ import annotations

import json
import os
from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal

from .constants import XRAY_TUN_DEFAULT_INTERFACE_NAME
from .subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text_pumped, sleep_with_events


@dataclass(slots=True)
class WindowsDefaultRouteContext:
    interface_alias: str


@dataclass(slots=True)
class WindowsTunInterface:
    interface_index: int
    ipv4_address: str
    ipv6_address: str


def _powershell_string_literal(value: str) -> str:
    return value.replace("'", "''")


def get_windows_default_route_context() -> WindowsDefaultRouteContext | None:
    if os.name != "nt":
        return None
    script = (
        "$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; "
        "if (-not $route) { exit 1 }; "
        "@{ interface_alias = $route.InterfaceAlias } | ConvertTo-Json -Compress"
    )
    try:
        result = run_text_pumped(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result_output_text(result) or "{}")
    except json.JSONDecodeError:
        return None
    interface_alias = str(payload.get("interface_alias") or "").strip()
    if not interface_alias:
        return None
    return WindowsDefaultRouteContext(interface_alias=interface_alias)


class XrayTunRouteManager(QObject):
    log_received = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._tun_interface_name = XRAY_TUN_DEFAULT_INTERFACE_NAME
        self._tun_interface_index = 0
        self._tun_gateway_v4 = ""
        self._has_ipv6_default_route = False

    def setup(self, tun_interface_name: str) -> bool:
        if os.name != "nt":
            return True

        self.cleanup()
        self._tun_interface_name = str(tun_interface_name or XRAY_TUN_DEFAULT_INTERFACE_NAME).strip() or XRAY_TUN_DEFAULT_INTERFACE_NAME

        interface = self._wait_for_tun_interface(self._tun_interface_name)
        if interface is None:
            self.log_received.emit(
                f"[xray-tun] TUN interface '{self._tun_interface_name}' did not appear or did not receive an IPv4 address"
            )
            return False

        self._tun_interface_index = interface.interface_index
        self._tun_gateway_v4 = interface.ipv4_address

        self._run_best_effort(
            ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/0", f"interface={self._tun_interface_index}"]
        )
        self._run_best_effort(["route", "delete", "0.0.0.0", "mask", "0.0.0.0", self._tun_gateway_v4])
        self._run_best_effort(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    f"Remove-NetRoute -DestinationPrefix '::/0' -InterfaceIndex {self._tun_interface_index} "
                    "-AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
                ),
            ]
        )

        # Keep the app-owned route patch minimal: the official Windows guidance
        # for Xray TUN documents adding an IPv4 default route manually.
        command = [
            "netsh",
            "interface",
            "ipv4",
            "add",
            "route",
            "0.0.0.0/0",
            f"interface={self._tun_interface_index}",
            f"nexthop={self._tun_gateway_v4}",
            "metric=0",
        ]
        result = self._run_logged(command)
        if result.returncode != 0:
            self.cleanup()
            return False

        if interface.ipv6_address:
            ipv6_command = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    f"$ErrorActionPreference='Stop'; "
                    f"New-NetRoute -DestinationPrefix '::/0' -InterfaceIndex {self._tun_interface_index} "
                    "-AddressFamily IPv6 -NextHop '::' -RouteMetric 0 -PolicyStore ActiveStore | Out-Null"
                ),
            ]
            ipv6_result = self._run_logged(ipv6_command)
            if ipv6_result.returncode != 0:
                self.cleanup()
                return False
            self._has_ipv6_default_route = True

        return True

    def cleanup(self) -> None:
        if os.name != "nt":
            return
        if self._tun_interface_index > 0:
            self._run_best_effort(
                ["netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/0", f"interface={self._tun_interface_index}"]
            )
        if self._tun_gateway_v4:
            self._run_best_effort(["route", "delete", "0.0.0.0", "mask", "0.0.0.0", self._tun_gateway_v4])
        if self._tun_interface_index > 0 and self._has_ipv6_default_route:
            self._run_best_effort(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        f"Remove-NetRoute -DestinationPrefix '::/0' -InterfaceIndex {self._tun_interface_index} "
                        "-AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
                    ),
                ]
            )
        self._tun_interface_index = 0
        self._tun_gateway_v4 = ""
        self._has_ipv6_default_route = False

    def _wait_for_tun_interface(self, tun_interface_name: str, max_wait_sec: float = 12.0) -> WindowsTunInterface | None:
        waited = 0.0
        while waited < max_wait_sec:
            interface = self._read_tun_interface(tun_interface_name)
            if interface is not None:
                return interface
            sleep_with_events(0.5)
            waited += 0.5
        return None

    @staticmethod
    def _read_tun_interface(tun_interface_name: str) -> WindowsTunInterface | None:
        escaped_name = _powershell_string_literal(tun_interface_name)
        script = (
            f"$ipv4 = Get-NetIPAddress -InterfaceAlias '{escaped_name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue "
            "| Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' } "
            "| Select-Object -First 1 InterfaceIndex, IPAddress; "
            "if (-not $ipv4) { exit 1 }; "
            f"$ipv6 = Get-NetIPAddress -InterfaceAlias '{escaped_name}' -AddressFamily IPv6 -ErrorAction SilentlyContinue "
            "| Where-Object { $_.IPAddress -and $_.IPAddress -notlike 'fe80::*' } "
            "| Select-Object -First 1 IPAddress; "
            "@{ interface_index = $ipv4.InterfaceIndex; ipv4_address = $ipv4.IPAddress; ipv6_address = ($ipv6.IPAddress) } "
            "| ConvertTo-Json -Compress"
        )
        try:
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result_output_text(result) or "{}")
        except json.JSONDecodeError:
            return None
        try:
            interface_index = int(payload.get("interface_index") or 0)
        except (TypeError, ValueError):
            interface_index = 0
        ipv4_address = str(payload.get("ipv4_address") or "").strip()
        ipv6_address = str(payload.get("ipv6_address") or "").strip()
        if interface_index <= 0 or not ipv4_address:
            return None
        return WindowsTunInterface(
            interface_index=interface_index,
            ipv4_address=ipv4_address,
            ipv6_address=ipv6_address,
        )

    def _run_logged(self, command: list[str]):
        result = run_text_pumped(command, timeout=5, creationflags=CREATE_NO_WINDOW)
        output = result_output_text(result).strip()
        self.log_received.emit(f"[xray-tun] {' '.join(command)} -> rc={result.returncode}")
        if output:
            self.log_received.emit(f"[xray-tun] {output}")
        return result

    def _run_best_effort(self, command: list[str]) -> None:
        try:
            self._run_logged(command)
        except Exception:
            pass
