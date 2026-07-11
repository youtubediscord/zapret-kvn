# sing-box Notes For Editor Work

## Purpose

This folder documents the subset of `sing-box` that matters for Zapret KVN and
for the planned migration from GUI-first routing controls to a text editor
inside the app.

The goal is not to mirror the entire upstream manual. The goal is to pin down:

- what `sing-box` JSON shape the app already generates;
- which upstream fields are relevant to us;
- which parts of the runtime config must remain app-managed;
- how to move from GUI forms to a text editor without losing safety.

## Source Baseline

Prepared on `2026-03-27` and updated on `2026-07-11` against these sources:

- local upstream source tree:
  `C:\Users\Admin\Downloads\sing-box-testing`
- upstream docs tree:
  `https://github.com/SagerNet/sing-box/tree/testing/docs/configuration`
- local app code:
  - `xray_fluent/singbox_config_builder.py`
  - `xray_fluent/singbox_manager.py`
  - `xray_fluent/app_controller.py`

Important version note:

- the bundled production core is `shtorm-7/sing-box-extended`
  `v1.13.14-extended-2.5.0` Windows AMD64 purego (upstream sing-box
  `1.13.14`); this variant keeps the Naive outbound and ships its matching
  `libcronet.dll`;
- the upstream docs above come from the `testing` branch, not from a frozen
  release tag;
- those docs already mention fields added in `sing-box 1.14.0`;
- the historical editor research targets `sing-box 1.14.x`, while runtime
  configs shipped by the app must validate against the bundled extended core;
- the current app code relies on fields that exist in `1.10.0+` and `1.12.0+`,
  but future editor work may safely target the `1.14.x` field set;
- if the bundled binary changes again later, re-check version-specific fields
  before exposing them in the editor.

## Current Project Reality

- `sing-box extended` is the default engine for ordinary SOCKS/HTTP proxy mode
  and remains the recommended TUN engine.
- The same raw sing-box profile is compiled into one of two capture modes:
  - proxy: app-owned SOCKS and HTTP inbounds replace source TUN/proxy inbounds;
  - TUN: source TUN remains active with a fresh app-owned interface name.
- Both capture modes support two outbound planner outcomes:
  - `native`: `sing-box` owns the selected outbound;
  - `hybrid`: `sing-box` remains the front runtime, while actual proxy traffic
    is relayed to a local Xray sidecar for transports our conversion layer does
    not map directly.
- The current conversion layer supports these outbound families:
  - `vless`
  - `vmess`
  - `trojan`
  - `shadowsocks`
  - `socks`
  - `http`
  - native sing-box `hysteria`, `hysteria2`, and `tuic` share links
  - native sing-box outbound JSON (`{"type": ...}`), passed through without
    conversion so extended-only outbound types are not rejected by the app
- The current conversion layer supports these transport/TLS features:
  - `tls`
  - `reality`
  - `ws`
  - `http` / `h2`
  - `grpc`
- The current conversion layer does not map Xray `xhttp` directly. When
  `streamSettings.network == "xhttp"`, the app switches to `hybrid` mode.

## What Is Documented Here

- [runtime-config.md](./runtime-config.md)
  Current `sing-box` runtime config shape used by the app, with the supported
  subset and the rule pipeline.
- [editor-integration.md](./editor-integration.md)
  Design notes for moving from GUI controls to a text editor while keeping
  runtime-only fields under app control.
- [template-format-v1.md](./template-format-v1.md)
  Concrete V1 template format for `sing-box` in the future in-app editor.
- [reference/](./reference/)
  Field-level reference for all sing-box configuration sections used by the
  app. Includes valid values, JSON structures, and complete examples.
  Targeted at sing-box 1.14.x.

## Main Conclusions

- Raw runtime JSON should not be treated as fully user-owned.
- Some fields must stay app-managed:
  - generated TUN interface name;
  - proxy-mode SOCKS/HTTP inbounds on `0.0.0.0` and their selected ports;
  - local protect port and password in hybrid mode;
  - Clash API listen address;
  - selected node materialization into the `proxy` outbound;
  - loop-prevention rules for the proxy server endpoint and protected
    processes;
  - log level and other local runtime details.
- The safest product shape is two-layer:
  - editable source text;
  - compiled runtime preview.
- If we choose to allow direct engine-JSON editing, we still need either:
  - placeholders/macros that the app resolves at launch time; or
  - a post-processing stage that injects runtime-managed fragments before start.

## Related Documents

- [../template-editor-v1.md](../template-editor-v1.md)
- [../profile-format-v1.md](../profile-format-v1.md)
- [../engine-capability-research.md](../engine-capability-research.md)
