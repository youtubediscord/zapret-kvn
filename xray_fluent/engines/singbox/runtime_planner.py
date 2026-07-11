from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import ipaddress
from ipaddress import ip_address
import json
import secrets
import socket
from pathlib import Path
from typing import Any

from ...runtime_security import generate_local_proxy_credentials, strip_singbox_proxy_inbounds
from ...constants import (
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    PROXY_HOST,
    SINGBOX_CLASH_API_PORT,
    SINGBOX_XRAY_RELAY_PORT,
    SS_PROTECT_PORT_END,
    SS_PROTECT_PORT_START,
)
from ...models import Node
from .config_builder import build_singbox_outbound, is_singbox_endpoint_node


_SS_PROTECT_METHOD = "chacha20-ietf-poly1305"
_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG = "__app_hybrid_protect_in"
_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG = "__app_hybrid_relay_in"
_APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG = "__app_hybrid_protect_out"
_PUBLIC_PROXY_LISTEN = "0.0.0.0"


@dataclass(frozen=True, slots=True)
class _ProxyPortSelection:
    requested_socks_port: int
    requested_http_port: int
    socks_port: int
    http_port: int


@dataclass(slots=True)
class SingboxDocumentState:
    source_path: Path
    text: str
    text_hash: str
    has_proxy_outbound: bool
    file_mtime_ns: int = 0
    file_size: int = 0


@dataclass(slots=True)
class ParsedSingboxDocument:
    source_path: Path
    text: str
    text_hash: str
    payload: dict[str, Any]
    has_proxy_outbound: bool


@dataclass(slots=True)
class SingboxXraySidecarPlan:
    relay_port: int
    relay_username: str
    relay_password: str
    protect_port: int
    protect_password: str
    config: dict[str, Any]


@dataclass(slots=True)
class SingboxRuntimePlan:
    outcome: str  # native_singbox | hybrid_xray_sidecar
    source_path: Path
    text_hash: str
    singbox_config: dict[str, Any]
    has_proxy_outbound: bool
    used_selected_node: bool
    xray_sidecar: SingboxXraySidecarPlan | None
    requested_socks_port: int = 0
    requested_http_port: int = 0
    socks_port: int = 0
    http_port: int = 0

    @property
    def is_hybrid(self) -> bool:
        return self.outcome == "hybrid_xray_sidecar"

    @property
    def proxy_ports_changed(self) -> bool:
        return (
            self.requested_socks_port > 0
            and self.requested_http_port > 0
            and (
                self.socks_port != self.requested_socks_port
                or self.http_port != self.requested_http_port
            )
        )


def inspect_singbox_document_text(source_path: Path, text: str) -> SingboxDocumentState:
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        has_proxy_outbound = _config_has_proxy_outbound(payload)
    return SingboxDocumentState(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        has_proxy_outbound=has_proxy_outbound,
    )


def parse_singbox_document(source_path: Path, text: str) -> ParsedSingboxDocument:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path.name}: {_format_json_error_message(text, exc)}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Корень sing-box config должен быть JSON-объектом.")
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = _config_has_proxy_outbound(payload)
    return ParsedSingboxDocument(
        source_path=source_path,
        text=text,
        text_hash=text_hash,
        payload=payload,
        has_proxy_outbound=has_proxy_outbound,
    )


def classify_node_for_singbox(node: Node | None) -> str:
    if node is None:
        return "native_singbox"
    if is_singbox_endpoint_node(node):
        return "native_singbox_endpoint"
    try:
        build_singbox_outbound(node, tag="proxy")
    except ValueError:
        return "hybrid_xray_sidecar"
    return "native_singbox"


def plan_singbox_runtime(
    document: ParsedSingboxDocument,
    node: Node | None,
    *,
    preferred_relay_port: int = 0,
    preferred_protect_port: int = 0,
    preferred_protect_password: str = "",
) -> SingboxRuntimePlan:
    runtime_config = deepcopy(document.payload)
    strip_singbox_proxy_inbounds(runtime_config)
    _ensure_singbox_metrics_contract(runtime_config)
    _ensure_singbox_tun_runtime_contract(runtime_config)

    return _plan_runtime_outbound(
        document,
        runtime_config=runtime_config,
        node=node,
        preferred_relay_port=preferred_relay_port,
        preferred_protect_port=preferred_protect_port,
        preferred_protect_password=preferred_protect_password,
    )


def plan_singbox_proxy_runtime(
    document: ParsedSingboxDocument,
    node: Node | None,
    *,
    allowed_proxy_ports: set[int] | None = None,
    preferred_relay_port: int = 0,
    preferred_protect_port: int = 0,
    preferred_protect_password: str = "",
) -> SingboxRuntimePlan:
    """Build the app-owned SOCKS/HTTP runtime from a raw sing-box profile."""
    runtime_config = deepcopy(document.payload)
    strip_singbox_proxy_inbounds(runtime_config)
    _strip_singbox_tun_inbounds(runtime_config)
    selection = _ensure_singbox_proxy_runtime_contract(
        runtime_config,
        allowed_proxy_ports=allowed_proxy_ports,
    )
    _ensure_singbox_metrics_contract(runtime_config)

    return _plan_runtime_outbound(
        document,
        runtime_config=runtime_config,
        node=node,
        preferred_relay_port=preferred_relay_port,
        preferred_protect_port=preferred_protect_port,
        preferred_protect_password=preferred_protect_password,
        requested_socks_port=selection.requested_socks_port,
        requested_http_port=selection.requested_http_port,
        socks_port=selection.socks_port,
        http_port=selection.http_port,
    )


def _plan_runtime_outbound(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    node: Node | None,
    preferred_relay_port: int,
    preferred_protect_port: int,
    preferred_protect_password: str,
    requested_socks_port: int = 0,
    requested_http_port: int = 0,
    socks_port: int = 0,
    http_port: int = 0,
) -> SingboxRuntimePlan:

    outbounds = runtime_config.get("outbounds")
    proxy_index = _find_proxy_outbound_index(outbounds)
    if proxy_index is None:
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=False,
            used_selected_node=False,
            xray_sidecar=None,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
        )

    if node is None:
        raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска sing-box.")

    if is_singbox_endpoint_node(node):
        # WireGuard/AWG живут в top-level `endpoints[]`; плейсхолдер `proxy`
        # из outbounds обязан удаляться, иначе sing-box падает на дубликате тега.
        proxy_endpoint = build_singbox_outbound(node, tag="proxy")
        assert isinstance(outbounds, list)
        del outbounds[proxy_index]
        _replace_or_append_tagged(_ensure_list(runtime_config, "endpoints"), "proxy", proxy_endpoint)
        _ensure_proxy_server_bootstrap_contract(runtime_config, proxy_endpoint, node.server)
        # Amnezia-серверы перехватывают порт 53 внутри туннеля: шаблонный
        # proxy-dns (tcp 8.8.8.8) получает REFUSED. Переключаемся на резолвер
        # туннеля (DNS= из .conf либо шлюз подсети интерфейса).
        node_outbound = node.outbound if isinstance(node.outbound, dict) else {}
        dns_override = select_endpoint_proxy_dns(
            node_outbound.get("_dns"),
            proxy_endpoint.get("address"),
        )
        if dns_override:
            _override_proxy_dns_server(runtime_config, dns_override)
        _validate_runtime_dns_contract(runtime_config)
        return SingboxRuntimePlan(
            outcome="native_singbox",
            source_path=document.source_path,
            text_hash=document.text_hash,
            singbox_config=runtime_config,
            has_proxy_outbound=True,
            used_selected_node=True,
            xray_sidecar=None,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
        )

    try:
        native_proxy = build_singbox_outbound(node, tag="proxy")
    except ValueError:
        return _plan_hybrid_runtime(
            document,
            runtime_config=runtime_config,
            proxy_index=proxy_index,
            node=node,
            preferred_relay_port=preferred_relay_port,
            preferred_protect_port=preferred_protect_port,
            preferred_protect_password=preferred_protect_password,
            requested_socks_port=requested_socks_port,
            requested_http_port=requested_http_port,
            socks_port=socks_port,
            http_port=http_port,
        )

    assert isinstance(outbounds, list)
    outbounds[proxy_index] = native_proxy
    _ensure_proxy_server_bootstrap_contract(runtime_config, native_proxy, node.server)
    _validate_runtime_dns_contract(runtime_config)
    return SingboxRuntimePlan(
        outcome="native_singbox",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        xray_sidecar=None,
        requested_socks_port=requested_socks_port,
        requested_http_port=requested_http_port,
        socks_port=socks_port,
        http_port=http_port,
    )


def _plan_hybrid_runtime(
    document: ParsedSingboxDocument,
    *,
    runtime_config: dict[str, Any],
    proxy_index: int,
    node: Node,
    preferred_relay_port: int,
    preferred_protect_port: int,
    preferred_protect_password: str,
    requested_socks_port: int = 0,
    requested_http_port: int = 0,
    socks_port: int = 0,
    http_port: int = 0,
) -> SingboxRuntimePlan:
    relay_port = preferred_relay_port if preferred_relay_port > 0 else _find_free_port(preferred=SINGBOX_XRAY_RELAY_PORT)
    excluded_ports = {relay_port}
    protect_port = preferred_protect_port if preferred_protect_port > 0 else _find_free_port(
        preferred=SS_PROTECT_PORT_START,
        port_range=range(SS_PROTECT_PORT_START, SS_PROTECT_PORT_END),
        excluded=excluded_ports,
    )
    protect_password = preferred_protect_password or _generate_ss_password()
    relay_username, relay_password = generate_local_proxy_credentials(prefix="sidecar")

    outbounds = runtime_config.setdefault("outbounds", [])
    assert isinstance(outbounds, list)
    outbounds[proxy_index] = {
        "type": "socks",
        "tag": "proxy",
        "server": PROXY_HOST,
        "server_port": relay_port,
        "username": relay_username,
        "password": relay_password,
        # Keep the relay on loopback so sing-box does not bind it to the
        # physical adapter via auto-detect rules.
        "inet4_bind_address": PROXY_HOST,
    }

    _replace_or_append_tagged(
        _ensure_list(runtime_config, "inbounds"),
        _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
        {
            "type": "shadowsocks",
            "tag": _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG,
            "listen": PROXY_HOST,
            "listen_port": protect_port,
            "method": _SS_PROTECT_METHOD,
            "password": protect_password,
        },
    )
    _ensure_hybrid_protect_route(runtime_config)
    _validate_runtime_dns_contract(runtime_config)

    sidecar = SingboxXraySidecarPlan(
        relay_port=relay_port,
        relay_username=relay_username,
        relay_password=relay_password,
        protect_port=protect_port,
        protect_password=protect_password,
        config=_build_xray_sidecar_config(
            node,
            relay_port=relay_port,
            relay_username=relay_username,
            relay_password=relay_password,
            protect_port=protect_port,
            protect_password=protect_password,
        ),
    )
    return SingboxRuntimePlan(
        outcome="hybrid_xray_sidecar",
        source_path=document.source_path,
        text_hash=document.text_hash,
        singbox_config=runtime_config,
        has_proxy_outbound=True,
        used_selected_node=True,
        xray_sidecar=sidecar,
        requested_socks_port=requested_socks_port,
        requested_http_port=requested_http_port,
        socks_port=socks_port,
        http_port=http_port,
    )


def _build_xray_sidecar_config(
    node: Node,
    *,
    relay_port: int,
    relay_username: str,
    relay_password: str,
    protect_port: int,
    protect_password: str,
) -> dict[str, Any]:
    if not isinstance(node.outbound, dict) or not node.outbound:
        raise ValueError("Выбранный сервер не содержит outbound JSON для xray sidecar.")
    if not str(node.outbound.get("protocol") or "").strip():
        raise ValueError("Выбранный сервер не содержит protocol для xray sidecar.")
    proxy_outbound = deepcopy(node.outbound)
    proxy_outbound["tag"] = "proxy"
    stream_settings = proxy_outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        stream_settings = {}
        proxy_outbound["streamSettings"] = stream_settings
    sockopt = stream_settings.get("sockopt")
    if not isinstance(sockopt, dict):
        sockopt = {}
        stream_settings["sockopt"] = sockopt
    sockopt["dialerProxy"] = _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": _APP_XRAY_SIDECAR_RELAY_INBOUND_TAG,
                "protocol": "socks",
                "listen": PROXY_HOST,
                "port": relay_port,
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": relay_username, "pass": relay_password}],
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            }
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": _APP_XRAY_SIDECAR_PROTECT_OUTBOUND_TAG,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": PROXY_HOST,
                            "port": protect_port,
                            "method": _SS_PROTECT_METHOD,
                            "password": protect_password,
                        }
                    ]
                },
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [_APP_XRAY_SIDECAR_RELAY_INBOUND_TAG],
                    "outboundTag": "proxy",
                }
            ],
        },
    }


def _is_domain_name(value: str) -> bool:
    host = str(value or "").strip()
    if not host:
        return False
    try:
        ip_address(host)
    except ValueError:
        return True
    return False


def _ensure_proxy_server_bootstrap_contract(
    payload: dict[str, Any],
    proxy_outbound: dict[str, Any],
    preferred_server: str,
) -> None:
    server = str(preferred_server or proxy_outbound.get("server") or "").strip()
    if not server:
        # Endpoint-конфиги (wireguard) не имеют top-level `server` — адрес живёт в peers[0].
        peers = proxy_outbound.get("peers")
        if isinstance(peers, list) and peers and isinstance(peers[0], dict):
            server = str(peers[0].get("address") or "").strip()
    if not _is_domain_name(server):
        return

    # Domain-based proxy servers must resolve through bootstrap-dns, otherwise
    # proxy-dns can recurse into the proxy outbound before the tunnel is ready.
    proxy_outbound["domain_resolver"] = "bootstrap-dns"

    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    direct_rule = {"domain": [server], "action": "route", "outbound": "direct"}

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        domain_value = rule.get("domain")
        if isinstance(domain_value, list) and server in [str(item) for item in domain_value]:
            rules[index] = direct_rule
            return

    insert_index = 0
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("action") == "sniff" or rule.get("protocol") == "dns":
            insert_index = index + 1
            continue
        break
    rules.insert(insert_index, direct_rule)


def _ensure_hybrid_protect_route(payload: dict[str, Any]) -> None:
    route = _ensure_dict(payload, "route")
    rules = _ensure_list(route, "rules")
    protect_rule = {"inbound": [_APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG], "outbound": "direct"}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_value = rule.get("inbound")
        if isinstance(inbound_value, list) and _APP_SINGBOX_HYBRID_PROTECT_INBOUND_TAG in [str(item) for item in inbound_value]:
            rules[index] = protect_rule
            return
    rules.insert(0, protect_rule)


def _ensure_singbox_metrics_contract(payload: dict[str, Any]) -> None:
    experimental = _ensure_dict(payload, "experimental")
    clash_api = _ensure_dict(experimental, "clash_api")
    clash_api["external_controller"] = f"127.0.0.1:{SINGBOX_CLASH_API_PORT}"


def _ensure_singbox_tun_runtime_contract(payload: dict[str, Any]) -> None:
    """Patch app-owned runtime fields for raw sing-box configs.

    The source document may keep a placeholder or stale interface name, but the
    runtime launch should always use a fresh xftun-prefixed adapter name. This
    avoids collisions during reconnect/apply while Windows is still releasing
    the previous wintun interface.
    """
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("type") or "").strip().lower() != "tun":
            continue
        inbound["interface_name"] = _generate_tun_interface_name()


def _strip_singbox_tun_inbounds(payload: dict[str, Any]) -> int:
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return 0
    filtered: list[Any] = []
    removed = 0
    for inbound in inbounds:
        if isinstance(inbound, dict) and str(inbound.get("type") or "").strip().lower() == "tun":
            removed += 1
            continue
        filtered.append(inbound)
    if removed:
        payload["inbounds"] = filtered
    return removed


def _ensure_singbox_proxy_runtime_contract(
    payload: dict[str, Any],
    *,
    allowed_proxy_ports: set[int] | None,
) -> _ProxyPortSelection:
    inbounds = _ensure_list(payload, "inbounds")
    excluded_ports: set[int] = set()
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        try:
            port = int(inbound.get("listen_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port > 0:
            excluded_ports.add(port)

    allowed = {int(port) for port in (allowed_proxy_ports or set()) if int(port) > 0}

    def port_available(port: int) -> bool:
        if port in excluded_ports:
            return False
        if port in allowed:
            return True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((_PUBLIC_PROXY_LISTEN, port))
            return True
        except OSError:
            return False

    selection: _ProxyPortSelection | None = None
    for attempt in range(500):
        socks_port = DEFAULT_SOCKS_PORT + attempt * 2
        http_port = DEFAULT_HTTP_PORT + attempt * 2
        if http_port > 65535:
            break
        if port_available(socks_port) and port_available(http_port):
            selection = _ProxyPortSelection(
                requested_socks_port=DEFAULT_SOCKS_PORT,
                requested_http_port=DEFAULT_HTTP_PORT,
                socks_port=socks_port,
                http_port=http_port,
            )
            break
    if selection is None:
        raise ValueError("Не удалось подобрать свободные локальные SOCKS/HTTP порты для sing-box.")

    inbounds.extend(
        [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": _PUBLIC_PROXY_LISTEN,
                "listen_port": selection.socks_port,
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": _PUBLIC_PROXY_LISTEN,
                "listen_port": selection.http_port,
            },
        ]
    )
    return selection


def select_endpoint_proxy_dns(
    dns_values: list[str] | None,
    endpoint_addresses: list[str] | None,
) -> str | None:
    """Выбор DNS-сервера туннеля для endpoint-нод (WG/AWG).

    Порядок (см. problems.md P1):
    1. первый ПРИВАТНЫЙ (RFC1918/ULA) адрес из `DNS =` conf'а;
    2. иначе шлюз из первого IPv4 CIDR адреса интерфейса (/32 считается /24,
       берётся первый хост сети: 10.8.0.78/32 -> 10.8.0.1);
    3. иначе первый адрес из `DNS =` как есть;
    4. иначе None — шаблонный proxy-dns не трогаем.
    """
    cleaned = [str(item).strip() for item in (dns_values or []) if str(item).strip()]

    for item in cleaned:
        try:
            candidate = ipaddress.ip_address(item)
        except ValueError:
            continue
        if candidate.is_private:
            return item

    for item in endpoint_addresses or []:
        try:
            interface = ipaddress.ip_interface(str(item).strip())
        except ValueError:
            continue
        if interface.version != 4:
            continue
        network = interface.network
        if network.prefixlen >= 31:
            network = ipaddress.ip_network(f"{interface.ip}/24", strict=False)
        try:
            return str(next(network.hosts()))
        except StopIteration:
            continue

    if cleaned:
        return cleaned[0]
    return None


def _override_proxy_dns_server(payload: dict[str, Any], server: str) -> None:
    dns = payload.get("dns")
    if not isinstance(dns, dict):
        return
    servers = dns.get("servers")
    if not isinstance(servers, list):
        return
    for index, item in enumerate(servers):
        if isinstance(item, dict) and str(item.get("tag") or "") == "proxy-dns":
            servers[index] = {
                "tag": "proxy-dns",
                "type": "udp",
                "server": server,
                "detour": "proxy",
            }
            return


def _validate_runtime_dns_contract(payload: dict[str, Any]) -> None:
    dns = payload.get("dns")
    server_tags: set[str] = set()
    if isinstance(dns, dict):
        for server in dns.get("servers") or []:
            if not isinstance(server, dict):
                continue
            tag = str(server.get("tag") or "").strip()
            if tag:
                server_tags.add(tag)

    missing_refs: list[str] = []

    def require_dns_tag(tag: str, owner: str) -> None:
        if not tag or tag in server_tags:
            return
        missing_refs.append(f"{owner} -> {tag}")

    route = payload.get("route")
    if isinstance(route, dict):
        require_dns_tag(_extract_dns_server_tag(route.get("default_domain_resolver")), "route.default_domain_resolver")

    if isinstance(dns, dict):
        require_dns_tag(_extract_dns_server_tag(dns.get("final")), "dns.final")
        for index, rule in enumerate(dns.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            require_dns_tag(_extract_dns_server_tag(rule.get("server")), f"dns.rules[{index}].server")

    for index, outbound in enumerate(payload.get("outbounds") or []):
        if not isinstance(outbound, dict):
            continue
        require_dns_tag(
            _extract_dns_server_tag(outbound.get("domain_resolver")),
            f"outbounds[{index}].domain_resolver",
        )

    for index, endpoint in enumerate(payload.get("endpoints") or []):
        if not isinstance(endpoint, dict):
            continue
        require_dns_tag(
            _extract_dns_server_tag(endpoint.get("domain_resolver")),
            f"endpoints[{index}].domain_resolver",
        )

    if not missing_refs:
        return

    details = "; ".join(dict.fromkeys(missing_refs))
    raise ValueError(
        "В sing-box конфиге отсутствует DNS-сервер с нужным tag. "
        f"Проверьте раздел dns.servers: {details}. "
        "Обычно для стандартного шаблона должны существовать теги `bootstrap-dns` и `proxy-dns`."
    )


def _find_proxy_outbound_index(outbounds: Any) -> int | None:
    if not isinstance(outbounds, list):
        return None
    for index, outbound in enumerate(outbounds):
        if isinstance(outbound, dict) and str(outbound.get("tag") or "") == "proxy":
            return index
    return None


def _config_has_proxy_outbound(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if _find_proxy_outbound_index(payload.get("outbounds")) is not None:
        return True
    # Endpoint с тегом `proxy` (например, wireguard) тоже считается наличием proxy.
    return _find_proxy_outbound_index(payload.get("endpoints")) is not None


def _replace_or_append_tagged(items: list[Any], tag: str, payload: dict[str, Any]) -> None:
    for index, item in enumerate(items):
        if isinstance(item, dict) and str(item.get("tag") or "") == tag:
            items[index] = payload
            return
    items.append(payload)


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    created: dict[str, Any] = {}
    parent[key] = created
    return created


def _ensure_list(parent: dict[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if isinstance(value, list):
        return value
    created: list[Any] = []
    parent[key] = created
    return created


def _extract_dns_server_tag(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("server") or "").strip()
    return ""


def _find_free_port(
    *,
    preferred: int,
    port_range: range | None = None,
    excluded: set[int] | None = None,
) -> int:
    excluded = excluded or set()
    candidates: list[int] = []
    if preferred > 0:
        candidates.append(preferred)
    if port_range is None:
        port_range = range(preferred, preferred + 100)
    for port in port_range:
        if port not in candidates:
            candidates.append(port)
    for port in candidates:
        if port <= 0 or port in excluded:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((PROXY_HOST, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free TCP port available near {preferred}")


def _generate_ss_password(length: int = 24) -> str:
    _, password = generate_local_proxy_credentials(prefix="protect", password_length=length)
    return password


def _generate_tun_interface_name() -> str:
    return f"xftun{secrets.token_hex(3)}"


def _format_json_error_message(text: str, exc: json.JSONDecodeError) -> str:
    lines = text.splitlines()
    line = lines[exc.lineno - 1] if 0 < exc.lineno <= len(lines) else ""
    caret = ""
    if line:
        caret = "\n" + (" " * max(0, exc.colno - 1)) + "^"
    return f"Ошибка синтаксиса JSON: {exc.msg} (строка {exc.lineno}, столбец {exc.colno})\n{line}{caret}".rstrip()
