# sing-box Runtime Config In Zapret KVN

## Scope

This document describes the `sing-box` JSON shape that Zapret KVN actually
builds today.

## Current Runtime Model

The user-facing product model is now:

- one raw `sing-box.json` editor;
- that raw config is the source of truth for TUN, routing, DNS, and the main
  sing-box-side graph;
- runtime planning patches only app-owned service fragments;
- if outbound tag `proxy` exists, the selected node may replace only that
  outbound;
- if the selected node cannot be rendered as native sing-box outbound
  (for example Xray `xhttp`), the app keeps the same raw `sing-box.json` as
  the front config and automatically adds an Xray sidecar only for the proxy
  path.

This means the older `RoutingSettings`-driven full builder described below is
legacy architecture context, not the preferred runtime path for the current raw
editor flow.

It is intentionally narrower than the upstream manual. We only document the
parts that matter for:

- TUN mode runtime generation;
- future text-editor support;
- compatibility with current `Node`, `RoutingSettings`, and `AppSettings`
  models.

Target baseline for future editor work:

- `sing-box 1.14.x`

This matters because the local source baseline comes from the upstream
`testing` branch, but the app-side design can now intentionally target the
`1.14.x` feature set instead of treating `1.14` fields as speculative.

## Upstream Root Shape

The upstream configuration root supports many top-level sections:

```json
{
  "log": {},
  "dns": {},
  "ntp": {},
  "certificate": {},
  "certificate_providers": [],
  "endpoints": [],
  "inbounds": [],
  "outbounds": [],
  "route": {},
  "services": [],
  "experimental": {}
}
```

Zapret KVN currently emits only this subset:

- `log`
- `inbounds`
- `outbounds`
- `route`
- `dns`
- `experimental`

Everything else is currently out of scope for app-generated `sing-box` runtime
configs.

## Two Runtime Modes

### Native mode

Used when the selected node can be converted directly from Xray-style outbound
JSON into a `sing-box` outbound.

Runtime shape:

```json
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "xftun<random>",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": false,
      "stack": "mixed"
    }
  ],
  "outbounds": [
    {
      "type": "<converted node>",
      "tag": "proxy",
      "domain_resolver": "proxy-dns"
    },
    {
      "type": "direct",
      "tag": "direct",
      "domain_resolver": "bootstrap-dns"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "proxy-dns",
    "final": "direct|proxy",
    "rules": []
  },
  "dns": {
    "servers": [
      {
        "tag": "bootstrap-dns",
        "type": "<udp|tcp|tls|https>",
        "server": "<bootstrap server>"
      },
      {
        "tag": "proxy-dns",
        "type": "<udp|tcp|tls|https>",
        "server": "<proxy dns server>",
        "detour": "proxy"
      }
    ],
    "final": "proxy-dns"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:<port>"
    }
  }
}
```

### Hybrid mode

Used when the selected node cannot be mapped directly by our current conversion
layer and the app must insert Xray as a sidecar. Today this happens when the
node uses Xray `xhttp`.

In hybrid mode, the `sing-box` config still owns TUN, but `proxy` is no longer
the remote server. Instead:

- `sing-box` sends proxied traffic to local Xray over SOCKS;
- `sing-box` exposes a local Shadowsocks protect inbound;
- Xray uses `dialerProxy` to send its own egress through that protect inbound.

The `sing-box` side looks like this:

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "xftun<random>",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": false,
      "stack": "mixed"
    },
    {
      "type": "shadowsocks",
      "tag": "tun-protect",
      "listen": "127.0.0.1",
      "listen_port": "<generated port>",
      "method": "chacha20-ietf-poly1305",
      "password": "<generated password>"
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": 11808,
      "inet4_bind_address": "127.0.0.1"
    },
    {
      "type": "direct",
      "tag": "direct",
      "domain_resolver": "bootstrap-dns"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
```

The important product consequence is that a future text editor cannot assume
that the on-screen `sing-box` JSON is the whole runtime truth. In hybrid mode,
the app also generates a second Xray config.

## Route Pipeline

The most important behavior is not just the fields, but rule execution order.

### Upstream semantics that matter

From upstream `route/route.go`, the router iterates rules in order. Some
actions are non-final and only mutate metadata for later rules. A final action
selects the route and stops the scan.

For our use case:

- `sniff` is non-final;
- `hijack-dns` is final;
- classic `outbound` routing is final;
- `reject` is final;
- `bypass` is final in the contexts where it applies.

This is why the first generated rule is `sniff`, not a plain route rule.

### Rule order generated by the app

Native mode:

1. `{"action": "sniff"}`
2. `{"protocol": "dns", "action": "hijack-dns"}`
3. protected-process bypass rule
4. proxy-server-endpoint bypass rule
5. optional LAN bypass rule
6. grouped process rules
7. service preset rules
8. direct domain/IP rules
9. block domain/IP rules
10. proxy domain/IP rules
11. `route.final` handles the unmatched remainder

Hybrid mode:

1. `{"action": "sniff"}`
2. `{"protocol": "dns", "action": "hijack-dns"}`
3. protected-process bypass rule
4. `{"inbound": ["tun-protect"], "outbound": "direct"}`
5. optional LAN bypass rule
6. grouped process rules
7. service preset rules
8. direct domain/IP rules
9. block domain/IP rules
10. proxy domain/IP rules
11. `route.final` handles the unmatched remainder

## Rule Fields We Already Use

The app already generates these upstream-supported match fields:

- `protocol`
- `inbound`
- `ip_is_private`
- `ip_cidr`
- `domain`
- `domain_suffix`
- `domain_keyword`
- `process_name`
- `process_path`
- `process_path_regex`

The app already generates these actions:

- classic route action via `outbound` shorthand
- `sniff`
- `hijack-dns`

### Important note about classic route shorthand

Upstream route docs now describe rules with explicit action objects, for
example:

```json
{
  "action": "route",
  "outbound": "direct"
}
```

But the upstream option structs still accept the classic shorthand where the
rule only contains `outbound`. That is what the app generates today. This is
valid and intentionally simple.

### Изменения в sing-box 1.14

Несколько полей, используемых текущим билдером, изменили статус в 1.14:

- `outbound` как shorthand в route rules (без `action`) — deprecated с 1.11.
  Продолжает работать, но при переходе на текстовый редактор следует
  генерировать `"action": "route", "outbound": "..."`.

- `outbound` как match-условие в DNS rules — **удалён** в 1.14. Был deprecated
  с 1.12. Маршрутизация DNS теперь только через `domain_resolver` на
  outbound'ах.

- `domain_resolver` на outbound'ах с доменным server address — **обязателен**
  с 1.14. В текущем билдере уже проставлен, но при ручном редактировании
  пользователь может его пропустить.

- `domain_strategy` в Dial Fields — **удалён** в 1.14. Заменён на
  `domain_resolver`.

## Mapping From App Models To sing-box

### `RoutingSettings.mode` and `tun_default_outbound`

`route.final` is derived as follows:

- `global` mode -> `proxy`
- `direct` mode -> `direct`
- rule mode -> `direct` or `proxy` depending on `tun_default_outbound`

### `RoutingSettings.bypass_lan`

When enabled:

```json
{
  "ip_is_private": true,
  "outbound": "direct"
}
```

### `RoutingSettings.process_rules`

Manual process rules are normalized into one of:

- `process_name`
- `process_path`
- `process_path_regex`

The builder also groups values by action, so multiple entries may collapse into
one rule containing an array of values.

### `RoutingSettings.process_preset_routes`

Process presets are expanded to `process_name` arrays and grouped by action.

### `RoutingSettings.service_routes`

Service presets are converted into `domain_suffix`, `domain`, `domain_keyword`,
or `ip_cidr` rules depending on the item prefix.

### `RoutingSettings.direct_domains`, `proxy_domains`, `block_domains`

These lists support these local prefixes:

- `domain:` -> `domain_suffix`
- `full:` -> `domain`
- `keyword:` -> `domain_keyword`
- plain CIDR -> `ip_cidr`
- plain domain -> `domain_suffix`

Local compatibility rule:

- `geosite:*` and `geoip:*` are skipped because the current app intentionally
  aligns with `sing-box >= 1.12`, and the target baseline is `1.14.x`, where
  those old route fields are already gone.

## Outbound Conversion Subset

The current app converts `Node.outbound` into a `sing-box` outbound only for
this subset:

- `vless`
- `vmess`
- `trojan`
- `shadowsocks`
- `socks`
- `http`

### TLS support mapped today

The current conversion layer maps:

- plain `tls`
- `reality`
- `utls.fingerprint`
- `server_name`
- `alpn`
- `allowInsecure` -> `tls.insecure`

### Transport support mapped today

The current conversion layer maps:

- `ws`
- `http`
- `h2`
- `grpc`

The current conversion layer does not map:

- Xray `xhttp`

When `xhttp` is detected, the app switches to hybrid mode instead of producing
an invalid native outbound.

## App-Managed Fields

These fields are runtime-owned today and should not silently become free-form
user inputs:

- `inbounds[0].interface_name`
- `inbounds[0].address`
- `inbounds[0].auto_route`
- `inbounds[0].strict_route`
- `inbounds[0].stack`
- hybrid-only protect inbound port and password
- local loop-prevention rules
- `route.auto_detect_interface`
- `dns.servers[].tag`
- `dns.servers[].detour`
- `experimental.clash_api.external_controller`
- fixed outbound tags: `proxy`, `direct`, `block`

This does not mean the future editor can never expose them. It means the app
must treat them as managed settings with explicit ownership, not as accidental
free text.

## Validation Checklist For Future Editor Work

Before launching `sing-box`, the app should validate at least this subset:

- JSON parses successfully.
- Required top-level sections for our chosen mode exist.
- Exactly one TUN inbound exists when TUN mode is requested.
- Outbound tags required by our runtime pipeline exist:
  - `proxy`
  - `direct`
  - `block`
- `route.final` points to a real outbound tag.
- DNS server tags used by `default_domain_resolver` and `dns.final` exist.
- Hybrid-only fragments are present only in hybrid mode.
- No unsupported local prefixes remain in domain lists after compilation.
- If the selected node requires hybrid mode, the native `proxy` outbound is not
  used by mistake.
- After materialization, the final config passes upstream structural validation.

## References

- Upstream docs:
  - `docs/configuration/index.md`
  - `docs/configuration/inbound/tun.md`
  - `docs/configuration/route/index.md`
  - `docs/configuration/route/rule.md`
  - `docs/configuration/route/rule_action.md`
  - `docs/configuration/dns/index.md`
  - `docs/configuration/experimental/clash-api.md`
  - `docs/configuration/outbound/index.md`
  - `docs/configuration/outbound/vless.md`
  - `docs/configuration/outbound/vmess.md`
  - `docs/configuration/outbound/trojan.md`
  - `docs/configuration/outbound/shadowsocks.md`
  - `docs/configuration/outbound/socks.md`
  - `docs/configuration/outbound/http.md`
  - `docs/configuration/shared/tls.md`
  - `docs/configuration/shared/v2ray-transport.md`
- Upstream source:
  - `route/route.go`
  - `option/route.go`
  - `option/rule.go`
  - `option/rule_action.go`
  - `option/tun.go`
  - `option/dns.go`
  - `option/experimental.go`
- Local app source:
  - `xray_fluent/singbox_config_builder.py`
  - `xray_fluent/singbox_manager.py`
- Field reference:
  - [reference/outbounds.md](./reference/outbounds.md)
  - [reference/tun-inbound.md](./reference/tun-inbound.md)
  - [reference/tls.md](./reference/tls.md)
  - [reference/transport.md](./reference/transport.md)
  - [reference/route-rules.md](./reference/route-rules.md)
  - [reference/dns.md](./reference/dns.md)
  - [reference/dial-fields.md](./reference/dial-fields.md)
  - [reference/examples.md](./reference/examples.md)
