import unittest

from xray_fluent.models import AppSettings


class ProxyEngineSettingsTests(unittest.TestCase):
    def test_new_and_legacy_states_default_to_singbox_proxy(self) -> None:
        self.assertEqual(AppSettings().proxy_engine, "singbox")
        self.assertEqual(AppSettings.from_dict({}).proxy_engine, "singbox")

    def test_proxy_engine_round_trip_keeps_explicit_xray_fallback(self) -> None:
        settings = AppSettings(proxy_engine="xray")
        restored = AppSettings.from_dict(settings.to_dict())
        self.assertEqual(restored.proxy_engine, "xray")


if __name__ == "__main__":
    unittest.main()
