from __future__ import annotations

from copy import deepcopy
from ipaddress import ip_network
from typing import Any

from .constants import (
    PROXY_HOST,
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    ROUTING_RULE,
    XRAY_STATS_API_PORT,
)
from .models import AppSettings, Node, RoutingSettings
from .service_presets import SERVICE_PRESETS_BY_ID


def _normalize_loglevel(value: str) -> str:
    normalized = value.lower().strip()
    if normalized == "warn":
        return "warning"
    if normalized in {"debug", "info", "warning", "error", "none"}:
        return normalized
    return "warning"


def _split_rule_items(items: list[str]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue

        if value.startswith(("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:")):
            domains.append(value)
            continue
        if value.startswith(("geoip:", "ip:")):
            ips.append(value)
            continue

        try:
            ip_network(value, strict=False)
            ips.append(value)
            continue
        except ValueError:
            pass

        domains.append(f"domain:{value}")

    return domains, ips


def _append_domain_ip_rule(rules: list[dict[str, Any]], items: list[str], outbound_tag: str) -> None:
    domains, ips = _split_rule_items(items)
    if domains:
        rules.append(
            {
                "type": "field",
                "domain": domains,
                "outboundTag": outbound_tag,
            }
        )
    if ips:
        rules.append(
            {
                "type": "field",
                "ip": ips,
                "outboundTag": outbound_tag,
            }
        )


def build_xray_config(node: Node, routing: RoutingSettings, settings: AppSettings) -> dict[str, Any]:
    proxy_outbound = deepcopy(node.outbound)
    proxy_outbound["tag"] = "proxy"

    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]

    if routing.bypass_lan:
        routing_rules.append(
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "direct",
            }
        )
        routing_rules.append(
            {
                "type": "field",
                "domain": ["geosite:private"],
                "outboundTag": "direct",
            }
        )

    _append_domain_ip_rule(routing_rules, routing.direct_domains, "direct")
    _append_domain_ip_rule(routing_rules, routing.block_domains, "block")
    _append_domain_ip_rule(routing_rules, routing.proxy_domains, "proxy")

    # Merge service preset domains
    service_direct: list[str] = []
    service_proxy: list[str] = []
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if not preset:
            continue
        if action == "direct":
            service_direct.extend(preset.domains)
        else:
            service_proxy.extend(preset.domains)
    _append_domain_ip_rule(routing_rules, service_proxy, "proxy")
    _append_domain_ip_rule(routing_rules, service_direct, "direct")

    if not settings.tun_mode:
        for pr in routing.process_rules:
            name = pr.get("process", "").strip()
            action = pr.get("action", "direct")
            if name:
                routing_rules.append({
                    "type": "field",
                    "process": [name],
                    "network": "tcp,udp",
                    "outboundTag": action if action in ("direct", "proxy", "block") else "direct",
                })

    mode = routing.mode

    if mode == ROUTING_GLOBAL:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )
    elif mode == ROUTING_DIRECT:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "direct",
            }
        )
    else:
        routing_rules.append(
            {
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "proxy",
            }
        )

    config: dict[str, Any] = {
        "log": {
            "loglevel": _normalize_loglevel(settings.log_level),
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": PROXY_HOST,
                "port": settings.socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "http-in",
                "listen": PROXY_HOST,
                "port": settings.http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "api",
                "listen": PROXY_HOST,
                "port": XRAY_STATS_API_PORT,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": PROXY_HOST,
                },
            },
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
            {
                "tag": "api",
                "protocol": "freedom",
                "settings": {},
            },
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
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules,
        },
    }

    if routing.dns_mode == "builtin":
        config["dns"] = {
            "servers": [
                "1.1.1.1",
                "8.8.8.8",
                "localhost",
            ],
            "queryStrategy": "UseIP",
        }

    return config
