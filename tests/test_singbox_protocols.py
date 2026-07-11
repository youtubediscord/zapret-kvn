import importlib.util
import json
from pathlib import Path
import sys
import unittest

from xray_fluent.link_parser import (
    LinkParseError,
    is_native_singbox_outbound,
    parse_links_text,
    parse_single,
    validate_node_outbound,
)


def _load_config_builder():
    path = Path(__file__).resolve().parents[1] / "xray_fluent" / "engines" / "singbox" / "config_builder.py"
    spec = importlib.util.spec_from_file_location("singbox_config_builder", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


config_builder = _load_config_builder()


class SingboxProtocolParserTests(unittest.TestCase):
    def test_hysteria2_alias_maps_tls_and_obfs(self) -> None:
        node = parse_single(
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1"
            "&obfs=salamander&obfs-password=cover#Fast%20HY2"
        )

        self.assertEqual(node.scheme, "hysteria2")
        self.assertEqual(node.name, "Fast HY2")
        self.assertEqual(node.server, "example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.outbound["type"], "hysteria2")
        self.assertEqual(node.outbound["password"], "secret")
        self.assertEqual(node.outbound["obfs"], {"type": "salamander", "password": "cover"})
        self.assertEqual(
            node.outbound["tls"],
            {"enabled": True, "server_name": "cdn.example.com", "insecure": True},
        )
        self.assertIsNone(validate_node_outbound(node))
        self.assertTrue(is_native_singbox_outbound(node))

    def test_hysteria2_preserves_userpass_and_port_hopping(self) -> None:
        node = parse_single(
            "hysteria2://user%3Apass@example.com:443,5000-5002/"
            "?hop_interval=20s#Port%20hop"
        )

        self.assertEqual(node.outbound["password"], "user:pass")
        self.assertEqual(node.outbound["server_ports"], ["443", "5000:5002"])
        self.assertEqual(node.outbound["hop_interval"], "20s")
        self.assertEqual(node.port, 443)

    def test_hysteria_maps_bandwidth_auth_and_tls(self) -> None:
        node = parse_single(
            "hysteria://example.com:8443/?auth=secret&upmbps=50&down_mbps=100"
            "&peer=cdn.example.com&alpn=h3,h2&obfs=mask#HY1"
        )

        self.assertEqual(node.outbound["type"], "hysteria")
        self.assertEqual(node.outbound["auth_str"], "secret")
        self.assertEqual(node.outbound["up_mbps"], 50)
        self.assertEqual(node.outbound["down_mbps"], 100)
        self.assertEqual(node.outbound["obfs"], "mask")
        self.assertEqual(node.outbound["tls"]["server_name"], "cdn.example.com")
        self.assertEqual(node.outbound["tls"]["alpn"], ["h3", "h2"])
        self.assertIsNone(validate_node_outbound(node))

    def test_tuic_maps_quic_options(self) -> None:
        node = parse_single(
            "tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:hello@example.com:443"
            "?congestion_control=bbr&reduce_rtt=1&udp_relay_mode=quic&sni=cdn.example.com#TUIC"
        )

        self.assertEqual(node.outbound["type"], "tuic")
        self.assertEqual(node.outbound["uuid"], "2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365")
        self.assertEqual(node.outbound["password"], "hello")
        self.assertEqual(node.outbound["congestion_control"], "bbr")
        self.assertEqual(node.outbound["udp_relay_mode"], "quic")
        self.assertTrue(node.outbound["zero_rtt_handshake"])
        self.assertEqual(node.outbound["tls"]["server_name"], "cdn.example.com")

    def test_native_json_selects_proxy_outbound(self) -> None:
        text = json.dumps(
            {
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {
                        "type": "anytls",
                        "tag": "proxy",
                        "server": "example.com",
                        "server_port": 443,
                        "password": "secret",
                        "tls": {"enabled": True},
                    },
                ]
            }
        )

        node = parse_single(text)

        self.assertEqual(node.scheme, "anytls")
        self.assertEqual(node.server, "example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.outbound["type"], "anytls")

    def test_pretty_printed_native_json_is_one_import_item(self) -> None:
        text = json.dumps(
            {
                "type": "anytls",
                "server": "example.com",
                "server_port": 443,
                "password": "secret",
                "tls": {"enabled": True},
            },
            indent=2,
        )

        nodes, errors = parse_links_text(text)

        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].scheme, "anytls")

    def test_native_outbound_is_passed_through_with_runtime_tag(self) -> None:
        node = parse_single(
            '{"type":"anytls","tag":"saved","server":"example.com",'
            '"server_port":443,"password":"secret","tls":{"enabled":true}}'
        )

        outbound = config_builder.build_singbox_outbound(node, tag="proxy")

        self.assertEqual(outbound["type"], "anytls")
        self.assertEqual(outbound["tag"], "proxy")
        self.assertEqual(node.outbound["tag"], "saved")

    def test_hysteria2_certificate_pin_is_not_silently_dropped(self) -> None:
        with self.assertRaisesRegex(LinkParseError, "pinSHA256"):
            parse_single("hy2://secret@example.com:443/?insecure=1&pinSHA256=deadbeef")

    def test_hysteria2_salamander_requires_password(self) -> None:
        with self.assertRaisesRegex(LinkParseError, "obfs-password"):
            parse_single("hy2://secret@example.com:443/?obfs=salamander")


if __name__ == "__main__":
    unittest.main()
