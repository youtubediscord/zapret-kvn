from __future__ import annotations

from copy import deepcopy
from typing import Any

_SUPPORTED_NATIVE_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks", "http"}


def build_singbox_outbound(node, *, tag: str = "proxy") -> dict[str, Any]:
    """Convert a stored node outbound into a native sing-box outbound."""
    protocol = str((node.outbound or {}).get("protocol") or "").lower()
    if protocol not in _SUPPORTED_NATIVE_PROTOCOLS:
        raise ValueError(
            f"Текущий сервер нельзя конвертировать в native sing-box outbound: protocol `{protocol or 'unknown'}`"
        )

    outbound = _convert_outbound(deepcopy(node.outbound))
    unsupported_transport = str(outbound.pop("_unsupported_transport", "") or "").strip()
    if unsupported_transport:
        raise ValueError(
            f"Текущий сервер нельзя конвертировать в native sing-box outbound: transport `{unsupported_transport}` не поддерживается"
        )

    outbound["tag"] = tag
    return outbound


def _convert_outbound(xray_ob: dict[str, Any]) -> dict[str, Any]:
    protocol = str(xray_ob.get("protocol") or "").lower()
    xray_settings = dict(xray_ob.get("settings") or {})
    stream = dict(xray_ob.get("streamSettings") or {})

    sb: dict[str, Any] = {"type": protocol}

    if protocol in ("vless", "vmess"):
        vnext = (xray_settings.get("vnext") or [{}])[0]
        sb["server"] = str(vnext.get("address") or "")
        sb["server_port"] = int(vnext.get("port") or 0)
        users = (vnext.get("users") or [{}])[0]
        sb["uuid"] = str(users.get("id") or "")
        if protocol == "vless":
            flow = str(users.get("flow") or "")
            if flow:
                sb["flow"] = flow
        else:
            sb["alter_id"] = int(users.get("alterId") or 0)
            sb["security"] = str(users.get("security") or "auto")

    elif protocol == "trojan":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["password"] = str(servers.get("password") or "")

    elif protocol == "shadowsocks":
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        sb["method"] = str(servers.get("method") or "")
        sb["password"] = str(servers.get("password") or "")

    elif protocol in ("socks", "http"):
        servers = (xray_settings.get("servers") or [{}])[0]
        sb["server"] = str(servers.get("address") or "")
        sb["server_port"] = int(servers.get("port") or 0)
        user_list = servers.get("users") or []
        if user_list:
            sb["username"] = str(user_list[0].get("user") or "")
            sb["password"] = str(user_list[0].get("pass") or "")

    _apply_tls(sb, stream)
    _apply_transport(sb, stream)
    return sb


def _apply_tls(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    security = str(stream.get("security") or "").lower()
    if security not in ("tls", "reality"):
        return

    tls: dict[str, Any] = {"enabled": True}

    if security == "reality":
        reality_settings = dict(stream.get("realitySettings") or {})
        tls["server_name"] = str(reality_settings.get("serverName") or "")
        fingerprint = str(reality_settings.get("fingerprint") or "")
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        public_key = str(reality_settings.get("publicKey") or "")
        short_id = str(reality_settings.get("shortId") or "")
        tls["reality"] = {"enabled": True, "public_key": public_key, "short_id": short_id}
    else:
        tls_settings = dict(stream.get("tlsSettings") or {})
        server_name = str(tls_settings.get("serverName") or "")
        if server_name:
            tls["server_name"] = server_name
        alpn = tls_settings.get("alpn")
        if alpn:
            tls["alpn"] = list(alpn)
        fingerprint = str(tls_settings.get("fingerprint") or "")
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        if tls_settings.get("allowInsecure", False):
            tls["insecure"] = True

    sb["tls"] = tls


def _apply_transport(sb: dict[str, Any], stream: dict[str, Any]) -> None:
    network = str(stream.get("network") or "tcp").lower()
    if network == "tcp":
        return

    if network == "ws":
        ws_settings = dict(stream.get("wsSettings") or {})
        transport: dict[str, Any] = {"type": "ws"}
        path = str(ws_settings.get("path") or "")
        if path:
            transport["path"] = path
        headers = dict(ws_settings.get("headers") or {})
        if headers:
            transport["headers"] = headers
        sb["transport"] = transport
        return

    if network in ("http", "h2"):
        http_settings = dict(stream.get("httpSettings") or stream.get("h2Settings") or {})
        transport = {"type": "http"}
        host = http_settings.get("host")
        if host:
            transport["host"] = list(host) if isinstance(host, list) else [str(host)]
        path = str(http_settings.get("path") or "")
        if path:
            transport["path"] = path
        sb["transport"] = transport
        return

    if network == "grpc":
        grpc_settings = dict(stream.get("grpcSettings") or {})
        transport = {"type": "grpc"}
        service_name = str(grpc_settings.get("serviceName") or "")
        if service_name:
            transport["service_name"] = service_name
        sb["transport"] = transport
        return

    if network == "xhttp":
        sb["_unsupported_transport"] = "xhttp"
