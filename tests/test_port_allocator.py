import unittest
import importlib.util
from pathlib import Path
import sys


def _load_port_allocator():
    path = Path(__file__).resolve().parents[1] / "xray_fluent" / "application" / "port_allocator.py"
    spec = importlib.util.spec_from_file_location("port_allocator", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


port_allocator = _load_port_allocator()
select_available_port = port_allocator.select_available_port
select_available_port_pair = port_allocator.select_available_port_pair


class PortAllocatorTests(unittest.TestCase):
    def test_selects_single_port_past_unavailable_range(self) -> None:
        unavailable = set(range(10786, 11086))
        result = select_available_port(
            10838,
            is_port_available=lambda port: port not in unavailable,
        )

        self.assertTrue(result.changed)
        self.assertEqual(result.requested_port, 10838)
        self.assertEqual(result.port, 11086)

    def test_keeps_available_pair(self) -> None:
        result = select_available_port_pair(
            1390,
            1391,
            is_port_available=lambda port: True,
        )

        self.assertFalse(result.changed)
        self.assertEqual(result.socks_port, 1390)
        self.assertEqual(result.http_port, 1391)

    def test_moves_consecutive_pair_past_unavailable_ports(self) -> None:
        unavailable = {1390, 1391, 1392}
        result = select_available_port_pair(
            1390,
            1391,
            is_port_available=lambda port: port not in unavailable,
        )

        self.assertTrue(result.changed)
        self.assertEqual(result.requested_socks_port, 1390)
        self.assertEqual(result.requested_http_port, 1391)
        self.assertEqual(result.socks_port, 1394)
        self.assertEqual(result.http_port, 1395)

    def test_skips_windows_excluded_range(self) -> None:
        unavailable = set(range(10786, 11086))
        result = select_available_port_pair(
            10838,
            10839,
            is_port_available=lambda port: port not in unavailable,
        )

        self.assertTrue(result.changed)
        self.assertEqual(result.socks_port, 11086)
        self.assertEqual(result.http_port, 11087)

    def test_updates_payload_without_reusing_other_inbound_port(self) -> None:
        payload = {
            "inbounds": [
                {"tag": "socks-in", "listen": "0.0.0.0", "port": 10838, "protocol": "socks"},
                {"tag": "http-in", "listen": "0.0.0.0", "port": 10839, "protocol": "http"},
                {"tag": "api", "listen": "127.0.0.1", "port": 11086, "protocol": "dokodemo-door"},
            ]
        }
        unavailable = set(range(10786, 11086))
        original_bindable = port_allocator.is_tcp_port_bindable
        port_allocator.is_tcp_port_bindable = lambda _host, port: port not in unavailable
        try:
            result = port_allocator.apply_proxy_port_auto_selection(payload)
        finally:
            port_allocator.is_tcp_port_bindable = original_bindable

        self.assertIsNotNone(result)
        self.assertTrue(result.changed)
        self.assertEqual(payload["inbounds"][0]["port"], 11088)
        self.assertEqual(payload["inbounds"][1]["port"], 11089)


if __name__ == "__main__":
    unittest.main()
