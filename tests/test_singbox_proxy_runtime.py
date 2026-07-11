import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from xray_fluent.engines.singbox.runtime_planner import (
    parse_singbox_document,
    plan_singbox_proxy_runtime,
)
from xray_fluent.link_parser import parse_single
from xray_fluent.models import Node


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"


class SingboxProxyRuntimeTests(unittest.TestCase):
    def _build_plan(self, link: str):
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        return plan_singbox_proxy_runtime(
            document,
            parse_single(link),
            allowed_proxy_ports={1390, 1391},
        )

    def test_default_proxy_runtime_replaces_tun_with_public_proxy_inbounds(self) -> None:
        plan = self._build_plan(
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1"
        )

        self.assertEqual(plan.outcome, "native_singbox")
        self.assertEqual((plan.socks_port, plan.http_port), (1390, 1391))
        self.assertFalse(any(item.get("type") == "tun" for item in plan.singbox_config["inbounds"]))
        self.assertEqual(
            [
                (item.get("type"), item.get("listen"), item.get("listen_port"))
                for item in plan.singbox_config["inbounds"]
            ],
            [
                ("socks", "0.0.0.0", 1390),
                ("http", "0.0.0.0", 1391),
            ],
        )
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(
            plan.singbox_config["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:19090",
        )

    def test_extended_core_accepts_new_protocol_proxy_plans(self) -> None:
        core = ROOT / "core" / "sing-box.exe"
        if not core.is_file():
            self.skipTest("bundled sing-box.exe is not present")

        links = (
            "hy2://secret@example.com:443/?sni=cdn.example.com&insecure=1",
            "hysteria://example.com:8443/?auth=secret&upmbps=50&downmbps=100&insecure=1",
            "tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:hello@example.com:443?insecure=1",
            '{"type":"anytls","server":"example.com","server_port":443,'
            '"password":"secret","tls":{"enabled":true,"insecure":true}}',
        )

        for link in links:
            with self.subTest(link=link.split(":", 1)[0]):
                plan = self._build_plan(link)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    suffix=".json",
                    dir=ROOT,
                    delete=False,
                ) as handle:
                    json.dump(plan.singbox_config, handle)
                    config_path = Path(handle.name)
                try:
                    runtime_path = str(config_path)
                    if os.name != "nt" and shutil.which("wslpath"):
                        runtime_path = subprocess.check_output(
                            ["wslpath", "-w", runtime_path],
                            text=True,
                        ).strip()
                    result = subprocess.run(
                        [str(core), "check", "-c", runtime_path],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                finally:
                    config_path.unlink(missing_ok=True)

    def test_xray_only_transport_uses_sidecar_behind_singbox_proxy(self) -> None:
        document = parse_singbox_document(
            TEMPLATE_PATH,
            TEMPLATE_PATH.read_text(encoding="utf-8"),
        )
        node = Node(
            name="XHTTP fallback",
            scheme="vless",
            server="example.com",
            port=443,
            outbound={
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "example.com",
                            "port": 443,
                            "users": [{"id": "11111111-1111-1111-1111-111111111111"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "example.com"},
                    "xhttpSettings": {"path": "/api"},
                },
            },
        )

        plan = plan_singbox_proxy_runtime(
            document,
            node,
            allowed_proxy_ports={1390, 1391},
        )

        self.assertTrue(plan.is_hybrid)
        self.assertIsNotNone(plan.xray_sidecar)
        self.assertEqual((plan.socks_port, plan.http_port), (1390, 1391))
        proxy = next(item for item in plan.singbox_config["outbounds"] if item.get("tag") == "proxy")
        self.assertEqual(proxy["type"], "socks")
        self.assertEqual(plan.xray_sidecar.config["outbounds"][0]["protocol"], "vless")


if __name__ == "__main__":
    unittest.main()
