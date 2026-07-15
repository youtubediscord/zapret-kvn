from __future__ import annotations

import struct
import unittest
from pathlib import Path

from xray_fluent.constants import APP_ICON_PATH


ROOT = Path(__file__).resolve().parents[1]
PNG_PATH = ROOT / "assets" / "app_icon.png"
ICO_PATH = ROOT / "assets" / "app_icon.ico"


class AppIconTests(unittest.TestCase):
    def test_runtime_icon_is_square_rgba_png(self) -> None:
        data = PNG_PATH.read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(data[12:16], b"IHDR")
        self.assertEqual(struct.unpack(">II", data[16:24]), (640, 640))
        self.assertEqual(data[25], 6)  # PNG color type 6: RGBA
        self.assertEqual(APP_ICON_PATH.resolve(), PNG_PATH.resolve())

    def test_windows_icon_contains_all_required_sizes(self) -> None:
        data = ICO_PATH.read_bytes()
        reserved, image_type, count = struct.unpack("<HHH", data[:6])
        self.assertEqual((reserved, image_type), (0, 1))

        sizes: set[tuple[int, int]] = set()
        for index in range(count):
            offset = 6 + index * 16
            width = data[offset] or 256
            height = data[offset + 1] or 256
            sizes.add((width, height))

        expected = {16, 20, 24, 32, 40, 48, 64, 128, 256}
        self.assertTrue({(size, size) for size in expected}.issubset(sizes))


if __name__ == "__main__":
    unittest.main()
