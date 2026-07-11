from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .models import Node


class LinkParseError(ValueError):
    pass


def parse_links_text(text: str) -> tuple[list[Node], list[str]]:
    stripped = text.strip()
    lines: list[str]
    if stripped.startswith("{"):
        try:
            json.loads(stripped)
        except json.JSONDecodeError:
            lines = [line.strip() for line in text.splitlines() if line.strip()]
        else:
            lines = [stripped]
    else:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
    nodes: list[Node] = []
    errors: list[str] = []

    for idx, line in enumerate(lines, start=1):
        try:
            node = parse_single(line)
            nodes.append(node)
        except Exception as exc:
            errors.append(f"Line {idx}: {exc}")

    return nodes, errors


def parse_single(raw: str) -> Node:
    text = raw.strip()
    if not text:
        raise LinkParseError("empty input")

    if text.startswith("{"):
        return _parse_json_outbound(text)

    scheme = urlsplit(text).scheme.lower()
    if scheme == "vless":
        return _parse_vless(text)
    if scheme == "vmess":
        return _parse_vmess(text)
    if scheme == "trojan":
        return _parse_trojan(text)
    if scheme == "ss":
        return _parse_shadowsocks(text)
    if scheme == "hysteria":
        return _parse_hysteria(text)
    if scheme in {"hy2", "hysteria2"}:
        return _parse_hysteria2(text)
    if scheme == "tuic":
        return _parse_tuic(text)
    if scheme in {"socks", "socks5"}:
        return _parse_socks(text)
    if scheme in {"http", "https"}:
        return _parse_http_proxy(text)

    raise LinkParseError(f"unsupported scheme: {scheme or 'unknown'}")


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    if not values:
        return default
    return values[0]


def _get_param(params: dict[str, str], *keys: str, default: str = "") -> str:
    empty_value: str | None = None
    for key in keys:
        if key in params:
            value = params[key]
            if value:
                return value
            if empty_value is None:
                empty_value = value

    lower_params = {str(key).lower(): value for key, value in params.items()}
    for key in keys:
        lowered = str(key).lower()
        if lowered in lower_params:
            value = lower_params[lowered]
            if value:
                return value
            if empty_value is None:
                empty_value = value
    if empty_value is not None:
        return empty_value
    return default


def _decode_b64(data: str) -> str:
    data = data.strip()
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(data.encode("utf-8"))
    except Exception:
        raw = base64.b64decode(data.encode("utf-8"))
    return raw.decode("utf-8")


def _clean_name(name: str, fallback: str) -> str:
    value = unquote(name).strip()
    return value if value else fallback


def _to_bool(value: str) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _url_auth(parsed) -> str:
    username = unquote(parsed.username or "")
    if parsed.password is None:
        return username
    return f"{username}:{unquote(parsed.password)}"


def _url_port_spec(parsed) -> str:
    host_port = parsed.netloc.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        closing = host_port.find("]")
        if closing < 0:
            return ""
        suffix = host_port[closing + 1 :]
        return suffix[1:] if suffix.startswith(":") else ""
    if ":" not in host_port:
        return ""
    return host_port.rsplit(":", 1)[1]


def _normalize_server_ports(value: str, *, default_port: int, allow_hopping: bool) -> tuple[int, list[str]]:
    raw = str(value or "").strip()
    if not raw:
        return default_port, []

    parts = [item.strip() for item in raw.replace("/", ",").split(",") if item.strip()]
    if not parts:
        return default_port, []
    if not allow_hopping and len(parts) != 1:
        raise LinkParseError("port hopping is not supported for this protocol")

    normalized: list[str] = []
    first_port = 0
    has_range = False
    for item in parts:
        separator = "-" if "-" in item else ":" if ":" in item else ""
        if separator:
            if not allow_hopping:
                raise LinkParseError("port hopping is not supported for this protocol")
            start_text, end_text = item.split(separator, 1)
            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError as exc:
                raise LinkParseError(f"invalid port range: {item}") from exc
            if not (1 <= start <= end <= 65535):
                raise LinkParseError(f"invalid port range: {item}")
            normalized.append(f"{start}:{end}")
            first_port = first_port or start
            has_range = True
            continue

        try:
            port = int(item)
        except ValueError as exc:
            raise LinkParseError(f"invalid port: {item}") from exc
        if not 1 <= port <= 65535:
            raise LinkParseError(f"invalid port: {item}")
        normalized.append(str(port))
        first_port = first_port or port

    if len(normalized) == 1 and not has_range:
        return first_port, []
    return first_port, normalized


def _link_server(parsed, *, default_port: int = 443, allow_hopping: bool = False) -> tuple[str, int, list[str]]:
    server = parsed.hostname or ""
    if not server:
        raise LinkParseError("missing server address")
    port, server_ports = _normalize_server_ports(
        _url_port_spec(parsed),
        default_port=default_port,
        allow_hopping=allow_hopping,
    )
    return server, port, server_ports


def _apply_server_ports(outbound: dict[str, Any], port: int, server_ports: list[str]) -> None:
    if server_ports:
        outbound["server_ports"] = server_ports
    else:
        outbound["server_port"] = port


def _parse_mbps(value: str, field: str) -> int:
    normalized = str(value or "").strip().lower().replace("mbps", "").strip()
    try:
        result = int(float(normalized))
    except (ValueError, OverflowError) as exc:
        raise LinkParseError(f"invalid {field}: {value}") from exc
    if result < 0:
        raise LinkParseError(f"invalid {field}: {value}")
    return result


def _set_hysteria_bandwidth(outbound: dict[str, Any], params: dict[str, str], field: str) -> None:
    mbps = _get_param(params, f"{field}_mbps", f"{field}mbps")
    if mbps:
        outbound[f"{field}_mbps"] = _parse_mbps(mbps, f"{field}_mbps")
        return
    value = _get_param(params, field)
    if not value:
        return
    if value.strip().isdigit():
        outbound[f"{field}_mbps"] = int(value)
    else:
        outbound[field] = value


def _native_node(link: str, scheme: str, outbound: dict[str, Any], server: str, port: int) -> Node:
    name = _clean_name(urlsplit(link).fragment, f"{scheme}-{server}:{port}")
    return Node(
        name=name,
        scheme=scheme,
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _build_stream_settings(params: dict[str, str], default_network: str = "tcp", default_security: str = "none") -> dict[str, Any]:
    network = (_get_param(params, "type", "net", default=default_network or "tcp") or "tcp").lower()
    security = (_get_param(params, "security", "tls", default=default_security or "none") or "none").lower()
    if security == "none" and _get_param(params, "tls") == "tls":
        security = "tls"

    stream: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    host = _get_param(params, "host")
    path = _get_param(params, "path")

    if network == "ws":
        ws_settings: dict[str, Any] = {}
        if path:
            ws_settings["path"] = path
        if host:
            ws_settings["headers"] = {"Host": host}
        stream["wsSettings"] = ws_settings
    elif network in {"http", "h2"}:
        http_settings: dict[str, Any] = {}
        if host:
            http_settings["host"] = [h.strip() for h in host.split(",") if h.strip()]
        if path:
            http_settings["path"] = path
        stream["httpSettings"] = http_settings
    elif network == "grpc":
        grpc_settings: dict[str, Any] = {}
        service_name = _get_param(params, "serviceName", "service_name")
        if service_name:
            grpc_settings["serviceName"] = service_name
        authority = _get_param(params, "authority")
        if authority:
            grpc_settings["authority"] = authority
        mode = _get_param(params, "mode")
        if mode == "multi":
            grpc_settings["multiMode"] = True
        stream["grpcSettings"] = grpc_settings
    elif network == "quic":
        stream["quicSettings"] = {
            "security": _get_param(params, "quicSecurity", "quic_security") or "none",
            "key": _get_param(params, "key") or "",
            "header": {"type": _get_param(params, "headerType", "header_type") or "none"},
        }
    elif network == "kcp":
        stream["kcpSettings"] = {
            "header": {"type": _get_param(params, "headerType", "header_type") or "none"},
        }

    if security == "tls":
        tls_settings: dict[str, Any] = {}
        sni = _get_param(params, "sni", "serverName", "server_name")
        if sni:
            tls_settings["serverName"] = sni
        alpn = _get_param(params, "alpn")
        if alpn:
            tls_settings["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
        fp = _get_param(params, "fp", "fingerprint")
        if fp:
            tls_settings["fingerprint"] = fp
        allow_insecure = _get_param(params, "allowInsecure", "allow_insecure")
        if allow_insecure:
            tls_settings["allowInsecure"] = _to_bool(allow_insecure)
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_settings: dict[str, Any] = {}
        sni = _get_param(params, "sni", "serverName", "server_name")
        if sni:
            reality_settings["serverName"] = sni
        fp = _get_param(params, "fp", "fingerprint")
        if fp:
            reality_settings["fingerprint"] = fp
        pbk = _get_param(params, "pbk", "publicKey", "public_key", "password")
        if pbk:
            reality_settings["publicKey"] = pbk
        sid = _get_param(params, "sid", "shortId", "short_id")
        if sid:
            reality_settings["shortId"] = sid
        spx = _get_param(params, "spx", "spiderX", "spider_x")
        if spx:
            reality_settings["spiderX"] = spx
        stream["realitySettings"] = reality_settings

    return stream


def _parse_vless(link: str) -> Node:
    parsed = urlsplit(link)
    query = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    params = {k: _first(query, k) for k in query}

    user_id = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443

    if not user_id or not server:
        raise LinkParseError("invalid vless link")

    user: dict[str, Any] = {
        "id": user_id,
        "encryption": _get_param(params, "encryption") or "none",
    }
    flow = _get_param(params, "flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "none")),
    }

    name = _clean_name(parsed.fragment, f"vless-{server}:{port}")
    return Node(
        name=name,
        scheme="vless",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def repair_node_outbound_from_link(node: Node) -> bool:
    link = str(node.link or "").strip()
    if not link:
        return False
    try:
        reparsed = parse_single(link)
    except Exception:
        return False
    if reparsed.outbound == node.outbound:
        return False
    node.outbound = reparsed.outbound
    if not node.scheme:
        node.scheme = reparsed.scheme
    if not node.server:
        node.server = reparsed.server
    if node.port <= 0:
        node.port = reparsed.port
    return True


def validate_node_outbound(node: Node) -> str | None:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    native_type = str(outbound.get("type") or "").strip().lower()
    protocol = str(outbound.get("protocol") or "").strip().lower()
    if native_type and not protocol:
        if native_type in {"hysteria", "hysteria2", "tuic"}:
            server = str(outbound.get("server") or "").strip()
            has_port = bool(outbound.get("server_port") or outbound.get("server_ports"))
            if not server or not has_port:
                return f"Сервер {node.name or native_type} не содержит адрес или порт для {native_type}."
        if native_type == "hysteria":
            if not (outbound.get("auth") or str(outbound.get("auth_str") or "")):
                return f"Сервер {node.name or native_type} не содержит auth для Hysteria."
            if not (outbound.get("up") or outbound.get("up_mbps")):
                return f"Сервер {node.name or native_type} не содержит upload bandwidth для Hysteria."
            if not (outbound.get("down") or outbound.get("down_mbps")):
                return f"Сервер {node.name or native_type} не содержит download bandwidth для Hysteria."
        elif native_type == "hysteria2" and not str(outbound.get("password") or ""):
            return f"Сервер {node.name or native_type} не содержит password для Hysteria2."
        elif native_type == "tuic" and not str(outbound.get("uuid") or ""):
            return f"Сервер {node.name or native_type} не содержит UUID для TUIC."
        return None

    stream_settings = outbound.get("streamSettings") if isinstance(outbound, dict) else None
    if not isinstance(stream_settings, dict):
        return None

    security = str(stream_settings.get("security") or "").strip().lower()
    if security != "reality":
        return None

    reality_settings = stream_settings.get("realitySettings")
    if not isinstance(reality_settings, dict):
        reality_settings = {}

    public_key = str(reality_settings.get("publicKey") or "").strip()
    if public_key:
        return None

    node_name = str(node.name or node.server or "безымянный сервер").strip()
    return (
        f"Сервер {node_name} не может быть запущен: для REALITY обязателен publicKey "
        "(параметр pbk в VLESS-ссылке), но в этой ссылке он пустой или отсутствует."
    )


def is_native_singbox_outbound(node: Node) -> bool:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    return bool(outbound.get("type")) and not bool(outbound.get("protocol"))


def _parse_vmess(link: str) -> Node:
    encoded = link[len("vmess://") :]
    payload = json.loads(_decode_b64(encoded))

    server = str(payload.get("add") or "")
    port = int(payload.get("port") or 443)
    user_id = str(payload.get("id") or "")
    if not server or not user_id:
        raise LinkParseError("invalid vmess link")

    security = str(payload.get("tls") or "none").lower()
    params = {
        "net": str(payload.get("net") or "tcp"),
        "type": str(payload.get("net") or "tcp"),
        "security": "tls" if security in {"tls", "reality"} else "none",
        "host": str(payload.get("host") or ""),
        "path": str(payload.get("path") or ""),
        "sni": str(payload.get("sni") or payload.get("host") or ""),
        "alpn": str(payload.get("alpn") or ""),
        "fp": str(payload.get("fp") or ""),
        "serviceName": str(payload.get("serviceName") or ""),
    }

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(payload.get("aid") or 0),
                            "security": str(payload.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network=params["net"], default_security=params["security"]),
    }

    name = _clean_name(str(payload.get("ps") or ""), f"vmess-{server}:{port}")
    return Node(
        name=name,
        scheme="vmess",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_trojan(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: _first(query, k) for k in query}

    password = unquote(parsed.username or "")
    server = parsed.hostname or ""
    port = parsed.port or 443
    if not password or not server:
        raise LinkParseError("invalid trojan link")

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": server,
                    "port": port,
                    "password": password,
                }
            ]
        },
        "streamSettings": _build_stream_settings(params, default_network="tcp", default_security=params.get("security", "tls")),
    }

    name = _clean_name(parsed.fragment, f"trojan-{server}:{port}")
    return Node(
        name=name,
        scheme="trojan",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_shadowsocks(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)

    method = ""
    password = ""
    server = parsed.hostname or ""
    port = parsed.port or 8388

    if parsed.username and parsed.password:
        method = unquote(parsed.username)
        password = unquote(parsed.password)
    elif parsed.username and not parsed.password:
        decoded = _decode_b64(parsed.username)
        if ":" not in decoded:
            raise LinkParseError("invalid shadowsocks credentials")
        method, password = decoded.split(":", 1)
    else:
        decoded = _decode_b64(parsed.netloc)
        parsed_decoded = urlsplit(f"ss://{decoded}")
        if parsed_decoded.username and parsed_decoded.password and parsed_decoded.hostname:
            method = unquote(parsed_decoded.username)
            password = unquote(parsed_decoded.password)
            server = parsed_decoded.hostname
            port = parsed_decoded.port or 8388
        else:
            raise LinkParseError("invalid shadowsocks link")

    if not method or not password or not server:
        raise LinkParseError("invalid shadowsocks link")

    plugin = _first(query, "plugin")
    outbound_server: dict[str, Any] = {
        "address": server,
        "port": port,
        "method": method,
        "password": password,
    }
    if plugin:
        outbound_server["plugin"] = plugin

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [outbound_server],
        },
    }

    name = _clean_name(parsed.fragment, f"ss-{server}:{port}")
    return Node(
        name=name,
        scheme="ss",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_hysteria(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {key: _first(query, key) for key in query}
    server, port, server_ports = _link_server(parsed, allow_hopping=True)

    port_override = _get_param(params, "mport", "ports")
    if port_override:
        port, server_ports = _normalize_server_ports(
            port_override,
            default_port=port,
            allow_hopping=True,
        )

    outbound: dict[str, Any] = {
        "type": "hysteria",
        "server": server,
    }
    _apply_server_ports(outbound, port, server_ports)

    auth = _get_param(params, "auth", "auth_str") or _url_auth(parsed)
    if auth:
        outbound["auth_str"] = auth
    _set_hysteria_bandwidth(outbound, params, "up")
    _set_hysteria_bandwidth(outbound, params, "down")

    obfs = _get_param(params, "obfs", "obfsParam", "obfs_param")
    if obfs:
        outbound["obfs"] = obfs

    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": _get_param(params, "peer", "sni") or server,
    }
    alpn = _get_param(params, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
    certificate_path = _get_param(params, "ca")
    if certificate_path:
        tls["certificate_path"] = certificate_path
    certificate = _get_param(params, "ca_str")
    if certificate:
        tls["certificate"] = certificate.splitlines()
    if _to_bool(_get_param(params, "insecure", "skip-cert-verify", "allow_insecure")):
        tls["insecure"] = True
    outbound["tls"] = tls

    if _to_bool(_get_param(params, "tfo", "tcp-fast-open", "tcp_fast_open")):
        outbound["tcp_fast_open"] = True
    hop_interval = _get_param(params, "hop_interval", "hopInterval")
    if hop_interval and server_ports:
        outbound["hop_interval"] = hop_interval

    return _native_node(link, "hysteria", outbound, server, port)


def _parse_hysteria2(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {key: _first(query, key) for key in query}
    server, port, server_ports = _link_server(parsed, allow_hopping=True)

    password = _url_auth(parsed)
    if not password:
        raise LinkParseError("invalid hysteria2 link: missing authentication password")

    port_override = _get_param(params, "mport", "ports")
    if port_override:
        port, server_ports = _normalize_server_ports(
            port_override,
            default_port=port,
            allow_hopping=True,
        )

    certificate_pin = _get_param(params, "pinSHA256", "pin_sha256")
    if certificate_pin:
        raise LinkParseError(
            "Hysteria2 pinSHA256 pins the whole certificate and cannot be safely converted "
            "to sing-box certificate_public_key_sha256"
        )

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "server": server,
        "password": password,
    }
    _apply_server_ports(outbound, port, server_ports)

    up = _get_param(params, "up", "up_mbps", "upmbps")
    down = _get_param(params, "down", "down_mbps", "downmbps")
    if up:
        outbound["up_mbps"] = _parse_mbps(up, "up_mbps")
    if down:
        outbound["down_mbps"] = _parse_mbps(down, "down_mbps")

    obfs_type = _get_param(params, "obfs").lower()
    if obfs_type and obfs_type not in {"none", "plain", "salamander"}:
        raise LinkParseError(f"unsupported Hysteria2 obfs type for sing-box: {obfs_type}")
    if obfs_type == "salamander":
        obfs_password = _get_param(params, "obfs-password", "obfs_password")
        if not obfs_password:
            raise LinkParseError("invalid hysteria2 link: salamander obfs requires obfs-password")
        outbound["obfs"] = {
            "type": "salamander",
            "password": obfs_password,
        }

    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": _get_param(params, "sni", "peer") or server,
    }
    if _to_bool(_get_param(params, "insecure", "skip-cert-verify", "allow_insecure")):
        tls["insecure"] = True
    outbound["tls"] = tls

    hop_interval = _get_param(params, "hop_interval", "hopInterval")
    if hop_interval and server_ports:
        outbound["hop_interval"] = hop_interval

    return _native_node(link, "hysteria2", outbound, server, port)


def _parse_tuic(link: str) -> Node:
    parsed = urlsplit(link)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = {key: _first(query, key) for key in query}
    server, port, _ = _link_server(parsed)

    uuid = unquote(parsed.username or "")
    if not uuid:
        raise LinkParseError("invalid tuic link: missing uuid")
    password = unquote(parsed.password or "")

    outbound: dict[str, Any] = {
        "type": "tuic",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    }
    if password:
        outbound["password"] = password

    congestion_control = _get_param(params, "congestion_control", "congestion-controller", "congestionControl")
    if congestion_control and congestion_control != "cubic":
        outbound["congestion_control"] = congestion_control

    udp_over_stream = _to_bool(_get_param(params, "udp_over_stream", "udp-over-stream"))
    if udp_over_stream:
        outbound["udp_over_stream"] = True
    else:
        udp_relay_mode = _get_param(params, "udp_relay_mode", "udp-relay-mode")
        if udp_relay_mode:
            outbound["udp_relay_mode"] = udp_relay_mode

    if _to_bool(_get_param(params, "zero_rtt_handshake", "reduce_rtt", "zero-rtt-handshake")):
        outbound["zero_rtt_handshake"] = True
    heartbeat = _get_param(params, "heartbeat_interval", "heartbeat")
    if heartbeat:
        outbound["heartbeat"] = heartbeat
    if _to_bool(_get_param(params, "tfo", "tcp-fast-open", "tcp_fast_open")):
        outbound["tcp_fast_open"] = True

    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": _get_param(params, "sni") or server,
    }
    if _to_bool(_get_param(params, "insecure", "skip-cert-verify", "allow_insecure")):
        tls["insecure"] = True
    if _to_bool(_get_param(params, "disable_sni")):
        tls["disable_sni"] = True
    alpn = _get_param(params, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
    outbound["tls"] = tls

    return _native_node(link, "tuic", outbound, server, port)


def _parse_socks(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or 1080
    if not server:
        raise LinkParseError("invalid socks link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "socks",
        "settings": {"servers": [server_item]},
    }

    name = _clean_name(parsed.fragment, f"socks-{server}:{port}")
    return Node(
        name=name,
        scheme="socks",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_http_proxy(link: str) -> Node:
    parsed = urlsplit(link)
    server = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not server:
        raise LinkParseError("invalid http proxy link")

    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    server_item: dict[str, Any] = {
        "address": server,
        "port": port,
    }
    if user:
        server_item["users"] = [{"user": user, "pass": password}]

    outbound = {
        "protocol": "http",
        "settings": {"servers": [server_item]},
    }

    name = _clean_name(parsed.fragment, f"http-{server}:{port}")
    return Node(
        name=name,
        scheme="http",
        server=server,
        port=port,
        link=link,
        outbound=outbound,
    )


def _parse_json_outbound(text: str) -> Node:
    payload = json.loads(text)

    outbound: dict[str, Any]
    if "protocol" in payload:
        outbound = dict(payload)
    elif "type" in payload:
        outbound = dict(payload)
    elif isinstance(payload.get("outbounds"), list) and payload["outbounds"]:
        candidates = [item for item in payload["outbounds"] if isinstance(item, dict)]
        if not candidates:
            raise LinkParseError("JSON `outbounds` must contain an object")
        selected = next((item for item in candidates if item.get("tag") == "proxy"), candidates[0])
        outbound = dict(selected)
    else:
        raise LinkParseError("JSON must contain `protocol`, `type`, or `outbounds`")

    protocol = str(outbound.get("protocol") or outbound.get("type") or "custom")
    tag = str(outbound.get("tag") or protocol)
    server = ""
    port = 0

    if outbound.get("type") and not outbound.get("protocol"):
        server = str(outbound.get("server") or "")
        try:
            port = int(outbound.get("server_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port <= 0:
            server_ports = outbound.get("server_ports") or []
            if not isinstance(server_ports, list):
                server_ports = [server_ports]
            if server_ports:
                first_port = str(server_ports[0]).split(":", 1)[0]
                try:
                    port = int(first_port)
                except ValueError:
                    port = 0
    else:
        settings = outbound.get("settings") or {}
        if protocol in {"vless", "vmess"}:
            vnext = (settings.get("vnext") or [{}])[0]
            server = str(vnext.get("address") or "")
            port = int(vnext.get("port") or 0)
        elif protocol in {"trojan", "shadowsocks", "socks", "http"}:
            servers = (settings.get("servers") or [{}])[0]
            server = str(servers.get("address") or "")
            port = int(servers.get("port") or 0)

    return Node(
        name=f"json-{tag}",
        scheme=protocol,
        server=server,
        port=port,
        link=text,
        outbound=outbound,
    )
