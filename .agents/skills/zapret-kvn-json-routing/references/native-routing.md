# Native Routing Contract

## Ownership map

| Layer | Paths | Authority |
|---|---|---|
| Shipped templates | `data/templates/sing-box/*.json`, `data/templates/xray/*.json` | Versioned defaults and reset/import sources |
| Active raw configs | `data/configs/sing-box/*.json`, `data/configs/xray/*.json` | Runtime routing and DNS source of truth |
| Runtime copies | `data/runtime/*.json` or manager-owned temporary files | Launch artifacts; do not author product policy here |
| Legacy GUI routing | `RoutingSettings`, presets, `engines/xray/config_builder.py` | Separate tun2socks/legacy path, not raw sing-box/Xray modes |

`application/profile_service.py` copies a selected or imported template into the corresponding active config. Reset performs the same copy. Saving in the raw editor writes the active config.

The self-updater preserves the installed `data/` directory. To deliver template updates through that boundary, `build.py` generates `assets/template-update` from the versioned `data/templates` tree. Before the UI starts, `template_sync.py` compares each same-path active config with the previously installed template, refreshes the active config only when their parsed JSON is equivalent, and then installs the new shipped template. A user-edited active config remains unchanged. The generated asset is transport, not a second authoring source.

## Mode map

| Mode | Routing owner | App-owned runtime work |
|---|---|---|
| System proxy to sing-box | Active sing-box JSON | Replace source proxy/TUN inbounds with public SOCKS/HTTP inbounds; allocate ports |
| sing-box TUN | Active sing-box JSON | Remove proxy inbounds; assign fresh TUN interface name |
| System/manual proxy to Xray | Active Xray JSON | Allocate proxy/API ports and add metrics contract |
| Xray TUN | Active Xray JSON | Add/keep TUN inbound, strip proxy inbounds, bind outbounds to the physical interface when required |
| sing-box hybrid Xray sidecar | Active sing-box JSON at the front | Route only the `proxy` outbound through the generated sidecar; preserve sing-box `direct` decisions |
| tun2socks fallback | GUI `RoutingSettings` and generated Xray config | Outside raw JSON ownership |

## Native sing-box rules

Use `route.rules` and upstream field names such as:

- `process_name`, `process_path`, `process_path_regex`;
- `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`;
- `ip_cidr`, `ip_is_private`;
- `rule_set`, `protocol`, `inbound`;
- `action` and `outbound`.

Prefer the current explicit route action:

```json
{
  "process_name": [
    "Example.exe",
    "example-helper.exe"
  ],
  "action": "route",
  "outbound": "direct"
}
```

Do not put Xray values such as `domain:example.com`, `full:example.com`, `geosite:*`, or `geoip:*` into a sing-box native rule. Use sing-box fields or native `rule_set` entries.

Keep this normal priority shape:

1. non-final `{"action": "sniff"}`;
2. DNS handling such as `{"protocol": "dns", "action": "hijack-dns"}`;
3. narrow protected/direct process rules;
4. LAN and other narrow rules;
5. broader process/domain/rule-set rules;
6. `route.final` for unmatched traffic.

Rules are evaluated in order. A final route action stops ordinary matching. Put a forced direct process rule before any broader proxy rule that can match the same traffic.

The runtime may insert narrowly scoped endpoint, metrics, or hybrid-protection rules ahead of source-authored policy. Those rules match app-owned inbounds or the selected proxy endpoint and must not become a second product-policy layer.

Ensure the referenced tag exists, normally:

```json
{
  "type": "direct",
  "tag": "direct",
  "domain_resolver": "bootstrap-dns"
}
```

## Native Xray rules

Use `routing.rules` with Xray field-rule keys such as:

- `type: "field"`;
- `process`;
- `domain` with Xray-native items such as `domain:`, `full:`, `regexp:`, or `geosite:` when supported by the bundled data/core;
- `ip` with CIDR, `geoip:`, or other Xray-native values;
- `network`, `inboundTag`, `port`;
- `outboundTag`.

Example process rule:

```json
{
  "type": "field",
  "process": [
    "Example.exe",
    "example-helper.exe"
  ],
  "network": "tcp,udp",
  "outboundTag": "direct"
}
```

Put project policy rules at the beginning of the template's `routing.rules`, before broad proxy rules. The runtime metrics rule may be inserted ahead of them for a dedicated metrics inbound; it does not match normal application traffic.

Ensure the referenced direct outbound exists, normally:

```json
{
  "tag": "direct",
  "protocol": "freedom",
  "settings": {}
}
```

## Reserved routing tags

- Keep `proxy` as the selected-node placeholder when the template expects the application to replace it.
- Keep `direct` for native direct egress.
- Keep `block` for the engine's native block/blackhole outbound.
- Do not rename app-owned tags beginning with `__app_` without tracing every runtime consumer.

## Files to trace before architecture changes

- `xray_fluent/application/profile_service.py`: template, active-config, reset, and save ownership.
- `xray_fluent/template_sync.py`: updater-safe delivery of shipped templates and preservation of user-edited active JSON.
- `xray_fluent/engines/singbox/runtime_planner.py`: proxy/TUN inbound contracts, selected outbound, bootstrap rule, and hybrid sidecar.
- `xray_fluent/application/xray_runtime_service.py`: raw Xray metrics, TUN, selected outbound, and loop-prevention contracts.
- `xray_fluent/ui/configs_page.py` and `ui/dashboard_page.py`: user-facing mode semantics.
- `docs/sing-box/runtime-config.md`: current raw-config model and route-order explanation.
- `docs/sing-box/reference/route-rules.md`: local upstream-aligned sing-box field reference.
- `docs/template-editor-v1.md` and `docs/sing-box/template-format-v1.md`: design context only; do not treat placeholders as implemented runtime behavior without source proof.
- `tests/test_yandex_music_direct_templates.py`: concrete cross-core example that checks native process rules and first-match priority in every shipped template.

## Verification checklist

1. Parse every changed JSON file.
2. Assert exact process/domain values, native action fields, and rule priority in a focused unit test.
3. Run `sing-box check` for changed sing-box templates.
4. Run `xray run -test` for changed Xray templates.
5. Run the relevant Python suite and `git diff --check`.
6. Test both automatic synchronization of untouched active configs and preservation of user-edited active configs.
7. Do not claim build or installed-runtime verification unless each was actually performed.
