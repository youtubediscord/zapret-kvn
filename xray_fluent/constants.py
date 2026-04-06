from __future__ import annotations

from pathlib import Path
import sys


APP_NAME = "Zapret Re-KVN"
APP_VERSION = "0.5.7"
STATE_SCHEMA_VERSION = 1

PROXY_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 10809
DEFAULT_XRAY_STATS_API_PORT = 19085
XRAY_GITHUB_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases"

ROUTING_GLOBAL = "global"
ROUTING_RULE = "rule"
ROUTING_DIRECT = "direct"
ROUTING_MODES = (ROUTING_GLOBAL, ROUTING_RULE, ROUTING_DIRECT)


def get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


BASE_DIR = get_base_dir()
DATA_DIR = BASE_DIR / "data"
TEMPLATES_DIR = DATA_DIR / "templates"
CONFIGS_DIR = DATA_DIR / "configs"
SINGBOX_TEMPLATES_DIR = TEMPLATES_DIR / "sing-box"
XRAY_TEMPLATES_DIR = TEMPLATES_DIR / "xray"
SINGBOX_CONFIGS_DIR = CONFIGS_DIR / "sing-box"
XRAY_CONFIGS_DIR = CONFIGS_DIR / "xray"
RUNTIME_DIR = DATA_DIR / "runtime"
LOG_DIR = DATA_DIR / "logs"
STATE_FILE = DATA_DIR / "state.enc"
XRAY_CONFIG_FILE = RUNTIME_DIR / "xray_config.json"
XRAY_DEFAULT_CONFIG_NAME = "default.json"
XRAY_PATH_DEFAULT = BASE_DIR / "core" / "xray.exe"
XRAY_TUN_DEFAULT_INTERFACE_NAME = "xray0"

SINGBOX_CONFIG_FILE = RUNTIME_DIR / "singbox_config.json"
SINGBOX_DEFAULT_CONFIG_NAME = "default.json"
SINGBOX_PATH_DEFAULT = BASE_DIR / "core" / "sing-box.exe"
SINGBOX_CLASH_API_PORT = 19090
SINGBOX_XRAY_RELAY_PORT = 11808

SPEED_TEST_URLS_BY_COUNTRY: dict[str, str] = {
    "nl": "https://ams.download.datapacket.com/100mb.bin",
    "de": "https://fra.download.datapacket.com/100mb.bin",
    "gb": "https://lon.download.datapacket.com/100mb.bin",
    "uk": "https://lon.download.datapacket.com/100mb.bin",
    "fr": "https://par.download.datapacket.com/100mb.bin",
    "se": "https://sto.download.datapacket.com/100mb.bin",
    "no": "https://osl.download.datapacket.com/100mb.bin",
    "dk": "https://sto.download.datapacket.com/100mb.bin",
    "fi": "https://sto.download.datapacket.com/100mb.bin",
    "at": "https://fra.download.datapacket.com/100mb.bin",
    "ch": "https://fra.download.datapacket.com/100mb.bin",
    "be": "https://ams.download.datapacket.com/100mb.bin",
    "lu": "https://fra.download.datapacket.com/100mb.bin",
    "pl": "https://ber.download.datapacket.com/100mb.bin",
    "cz": "https://ber.download.datapacket.com/100mb.bin",
    "ie": "https://lon.download.datapacket.com/100mb.bin",
    "ru": "https://speedtest.selectel.ru/100MB",
    "us": "https://ams.download.datapacket.com/100mb.bin",
}
SPEED_TEST_DEFAULT_URL = "https://fra.download.datapacket.com/100mb.bin"
SPEED_TEST_TIMEOUT = 20  # seconds per single measurement
SPEED_TEST_ROUNDS = 3    # number of measurements per node (best avg of N-1)
SPEED_TEST_TEMP_SOCKS_PORT = 19100
SPEED_TEST_TEMP_HTTP_PORT = 19101

SS_PROTECT_PORT_START = 19200
SS_PROTECT_PORT_END = 19300
