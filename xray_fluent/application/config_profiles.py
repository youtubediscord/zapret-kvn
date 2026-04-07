from __future__ import annotations

import json
from pathlib import Path


def normalize_relative_json_path(value: str | Path | None, default_name: str) -> str:
    raw = str(value or "").strip().replace("\\", "/")
    if not raw:
        return default_name

    parts = [part for part in Path(raw).parts if part not in ("", ".", "..", "/")]
    relative = Path(*parts) if parts else Path(default_name)
    if not relative.suffix:
        relative = relative.with_suffix(".json")
    return relative.as_posix()


def resolve_profile_path(
    base_dir: Path,
    value: str | Path | None,
    default_name: str,
    *,
    label: str,
) -> Path:
    base_dir = base_dir.resolve()
    normalized = normalize_relative_json_path(value, default_name)
    if value is None or not str(value).strip():
        resolved = (base_dir / normalized).resolve()
    else:
        candidate = Path(value)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (base_dir / normalized).resolve()

    if not resolved.suffix:
        resolved = resolved.with_suffix(".json")

    try:
        resolved.relative_to(base_dir)
    except ValueError as exc:
        raise ValueError(f"Файл {label} должен находиться в {base_dir.as_posix()}/") from exc
    return resolved


def default_singbox_config_text() -> str:
    payload = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "xftun",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": False,
                "stack": "mixed",
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "proxy"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"auto_detect_interface": True, "final": "direct"},
    }
    route = payload["route"]
    assert isinstance(route, dict)
    route["rule_set"] = [
        {
            "type": "remote",
            "tag": "geosite-category-ru",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-category-ru.srs",
            "download_detour": "proxy",
            "update_interval": "24h",
        },
        {
            "type": "remote",
            "tag": "geoip-ru",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru.srs",
            "download_detour": "proxy",
            "update_interval": "24h",
        },
    ]
    route["rules"] = [
        {
            "action": "sniff",
        },
        {
            "protocol": "dns",
            "action": "hijack-dns",
        },
        {
            "rule_set": ["geosite-category-ru", "geoip-ru"],
            "action": "route",
            "outbound": "direct",
        },
    ]
    payload["dns"] = {
        "servers": [
            {
                "tag": "bootstrap-dns",
                "type": "udp",
                "server": "1.1.1.1",
            },
            {
                "tag": "proxy-dns",
                "type": "tcp",
                "server": "8.8.8.8",
                "detour": "proxy",
            },
        ],
        "rules": [
            {
                "rule_set": ["geosite-category-ru"],
                "action": "route",
                "server": "bootstrap-dns",
            }
        ],
        "final": "proxy-dns",
    }
    payload["experimental"] = {
        "cache_file": {
            "enabled": True,
        }
    }
    return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"


def default_xray_config_text(
    *,
    proxy_host: str,
    socks_port: int,
    http_port: int,
    api_port: int,
) -> str:
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": proxy_host,
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
            },
            {
                "tag": "http-in",
                "listen": proxy_host,
                "port": http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True},
            },
            {
                "tag": "api",
                "listen": proxy_host,
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": proxy_host},
            },
        ],
        "outbounds": [
            {"tag": "proxy", "protocol": "freedom", "settings": {}},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
            {"tag": "api", "protocol": "freedom", "settings": {}},
        ],
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "network": "tcp,udp",
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": ["geosite:private"],
                    "network": "tcp,udp",
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": ["geosite:category-ru"],
                    "network": "tcp,udp",
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ip": ["geoip:ru"],
                    "network": "tcp,udp",
                    "outboundTag": "direct",
                },
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
            ],
        },
    }
    return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"


def format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
    lines = text.splitlines()
    line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
    caret = ""
    if line:
        caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
    return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()


def validate_json_text(text: str) -> tuple[bool, str]:
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return False, format_json_error_message(text, exc)
    return True, "JSON корректен."
