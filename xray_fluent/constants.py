from __future__ import annotations

from pathlib import Path
import sys


APP_NAME = "zapret kvn"
APP_VERSION = "0.4.22"
STATE_SCHEMA_VERSION = 1

PROXY_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 8080
XRAY_STATS_API_PORT = 19085
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
RUNTIME_DIR = DATA_DIR / "runtime"
LOG_DIR = DATA_DIR / "logs"
STATE_FILE = DATA_DIR / "state.enc"
XRAY_CONFIG_FILE = RUNTIME_DIR / "xray_config.json"
XRAY_PATH_DEFAULT = BASE_DIR / "core" / "xray.exe"

SINGBOX_CONFIG_FILE = RUNTIME_DIR / "singbox_config.json"
SINGBOX_PATH_DEFAULT = BASE_DIR / "core" / "sing-box.exe"
SINGBOX_CLASH_API_PORT = 19090

SPEED_TEST_URL = "https://speedtest.selectel.ru/100MB"
SPEED_TEST_TIMEOUT = 20  # seconds per single measurement
SPEED_TEST_ROUNDS = 3    # number of measurements per node (best avg of N-1)
SPEED_TEST_TEMP_SOCKS_PORT = 19100
SPEED_TEST_TEMP_HTTP_PORT = 19101

SS_PROTECT_PORT_START = 19200
SS_PROTECT_PORT_END = 19300
