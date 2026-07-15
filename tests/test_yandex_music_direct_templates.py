from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
YANDEX_MUSIC_PROCESSES = {"Яндекс Музыка.exe", "yandexmusic.exe"}


class YandexMusicDirectTemplateTests(unittest.TestCase):
    def test_all_singbox_templates_route_yandex_music_direct_first(self) -> None:
        template_dir = ROOT / "data" / "templates" / "sing-box"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                rules = payload["route"]["rules"]
                direct_index = next(
                    index
                    for index, rule in enumerate(rules)
                    if set(rule.get("process_name", [])) == YANDEX_MUSIC_PROCESSES
                )
                direct_rule = rules[direct_index]

                self.assertEqual(direct_rule.get("action"), "route")
                self.assertEqual(direct_rule.get("outbound"), "direct")
                self.assertTrue(
                    all(rule.get("action") in {"sniff", "hijack-dns"} for rule in rules[:direct_index]),
                    "Yandex Music direct must precede all user routing rules",
                )

    def test_all_xray_templates_route_yandex_music_direct_first(self) -> None:
        template_dir = ROOT / "data" / "templates" / "xray"

        for path in sorted(template_dir.glob("*.json")):
            with self.subTest(template=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                direct_rule = payload["routing"]["rules"][0]

                self.assertEqual(direct_rule.get("type"), "field")
                self.assertEqual(set(direct_rule.get("process", [])), YANDEX_MUSIC_PROCESSES)
                self.assertEqual(direct_rule.get("network"), "tcp,udp")
                self.assertEqual(direct_rule.get("outboundTag"), "direct")


if __name__ == "__main__":
    unittest.main()
