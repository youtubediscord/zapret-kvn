---
name: zapret-kvn-json-routing
description: Preserve and edit Zapret KVN native raw JSON routing for sing-box and Xray. Use when working in /mnt/g/Privacy/Xray-windows-64 on data/templates or data/configs JSON; adding direct, proxy, or block rules; matching processes, paths, domains, IPs, or rule sets; changing system-proxy or sing-box/Xray TUN behavior; synchronizing templates with active configs; or deciding whether routing belongs in JSON versus Python runtime code. Treat the original core JSON formats as the source of truth and prevent custom routing DSLs, overlays, generated policy layers, or hidden route injection.
---

# Zapret KVN Native JSON Routing

## Keep the architecture native

- Treat the active raw sing-box or Xray JSON as the runtime routing and DNS source of truth.
- Express product routing policy directly in the original core schema.
- Do not create an app-specific routing DSL, JSON overlay, merge layer, placeholder compiler, generated policy block, or hidden Python route injection.
- Do not route raw-config modes through `RoutingSettings`, `service_presets.py`, `process_presets.py`, or `engines/xray/config_builder.py`. Those belong to the separate legacy GUI/tun2socks path.
- Treat `${APP_ROUTE_RULES}` and similar material in design documents as unimplemented design context unless current source proves otherwise.
- Keep runtime mutations limited to app-owned transport and safety contracts already required by the architecture: proxy/TUN inbounds, metrics API, selected `proxy` outbound replacement, endpoint bootstrap, hybrid sidecar protection, interface binding, and port allocation.

## Read the project contract first

Before editing or reviewing routing, read [references/native-routing.md](references/native-routing.md) completely. Then inspect the exact JSON files in scope and the current runtime path rather than assuming template state equals active installed state.

## Follow this workflow

1. Read `AGENTS.md` and preserve its build, UI, and `0.0.0.0` constraints.
2. Identify the engine and mode: sing-box proxy, sing-box TUN, Xray proxy, Xray TUN, hybrid sing-box/Xray sidecar, or legacy tun2socks.
3. Identify the proof surface:
   - edit `data/templates/<engine>/*.json` for shipped/versioned defaults;
   - inspect `data/configs/<engine>/*.json` for an existing active development copy;
   - inspect the installed application's `data/configs` for live installed behavior;
   - never assume rebuilding overwrites an existing active config.
4. Write the rule in the engine's native schema. Do not mechanically copy keys between sing-box and Xray.
5. Put narrow high-priority rules before broader process/domain rules and catch-all proxy rules. Preserve required sniff and DNS handling ahead of ordinary sing-box traffic rules.
6. Update every shipped template variant when the requested behavior is a project-wide invariant.
7. Add a focused regression test for rule presence, exact values, action, and order.
8. Validate JSON with the bundled matching core, run focused/full Python tests as appropriate, and run `git diff --check`.
9. Keep proof levels distinct: template updated, active config synchronized, core-valid, tests green, build-ready, built, and installed-runtime verified are separate claims.

## Preserve source ownership

- Keep `data/templates/sing-box/*.json` and `data/templates/xray/*.json` as the versioned shipping templates.
- Keep `data/configs/sing-box/*.json` and `data/configs/xray/*.json` as user-editable active copies used by runtime.
- Let template selection/import/reset copy template text into the active config through `application/profile_service.py`.
- Do not silently overwrite an existing active user config after a template-only change. Tell the user to reselect or reset the template, or update the exact active config only when that state is explicitly in scope.
- Remember that `build.py` preserves `data/` and merges tracked templates; a build alone does not refresh an existing active copy.

## Respect mode boundaries

- Use the same active sing-box JSON routing in system-proxy and sing-box TUN modes; only app-owned inbounds differ.
- Use the same active Xray JSON routing in system-proxy/manual-proxy and Xray TUN modes; Xray TUN adds its app-owned TUN contract.
- Keep the sing-box raw config in front during hybrid sidecar operation. Let sing-box decide `direct` versus `proxy`; use Xray sidecar only for the selected proxy path.
- Treat tun2socks as a separate fallback path driven by GUI `RoutingSettings`; do not claim a raw JSON template change covers tun2socks.
- State that system-proxy rules affect traffic that actually enters the local SOCKS/HTTP inbound. Traffic an application already sends outside the system proxy is already outside that proxy path.

## Validate without broadening scope

Use the project cores and tests:

```bash
for file in data/templates/sing-box/*.json; do
  ./core/sing-box.exe check -c "$file" || exit
done

for file in data/templates/xray/*.json; do
  ./core/xray.exe run -test -c "$file" || exit
done

python3 -m unittest discover -s tests -v
git diff --check
```

If direct PE execution fails under WSL, invoke the executable through `cmd.exe` with a Windows path. Do not use a PowerShell pipeline for PE validation.

Do not build or smoke-start the GUI unless the user explicitly asks. When a build is requested, follow `AGENTS.md` and use `python build.py`.
