# Project Rules

- Do not create new Git branches unless the user explicitly asks for one. By default, keep work on `main` and commit/push requested changes directly to `main`.
- Production builds are created remotely by the `Build & Release` GitHub Actions workflow after a push to `main`. Do not run a local build unless the user explicitly asks for one; validate source changes locally with the relevant tests and core config checks before pushing.
- For sing-box and Xray proxy/native TUN modes, the active raw JSON config is the routing and DNS source of truth. Keep versioned defaults under `data/templates/sing-box` and `data/templates/xray`, using only the original native core schemas.
- Do not introduce a custom routing DSL, overlay, `${APP_ROUTE_RULES}`-style compiler, or hidden Python injection of product routing policy. Runtime mutations must stay limited to app-owned transport and safety contracts.
- The same active raw JSON owns routing for an engine's proxy and native TUN modes. The hybrid Xray sidecar owns only its `proxy` path, while tun2socks remains a separate legacy path.
- Remote builds preserve existing active files under `data/configs`; changing a shipped template does not migrate an installed active config automatically. Existing installations need an explicit reset or template reselection to receive template changes.
- For JSON routing work, follow the project skill `$zapret-kvn-json-routing` in `.agents/skills/zapret-kvn-json-routing/SKILL.md`.
- Keep page-level surfaces transparent. Do not add local background fills or page/root/scroll-area style sheets that block Windows 11 Mica.
- Prefer built-in `qfluentwidgets` appearance over custom page styling. Add local UI styling only when the user explicitly asks for it or when the library cannot provide the needed result.
- Do not force `WA_TranslucentBackground` on full pages, scroll areas, or their viewports unless it is explicitly needed and visually verified; prefer the same built-in page behavior used by working screens.
- Do not rebuild or smoke-start the app automatically after UI changes. The user will build it manually unless they explicitly ask for a build or startup verification.
- Do not change Xray proxy template/config `listen` addresses from `0.0.0.0` to localhost-only. In this project that is an intentional feature so the app can share the local proxy with other devices/apps when the user wants proxy distribution.
- When a build is explicitly requested, use the project builder `python build.py` from the repo root instead of calling PyInstaller directly.
- Before building, make sure `dist/ZapretKVN/ZapretKVN.exe` is not running; if needed, stop `ZapretKVN.exe` first or the clean step can fail because the old binary is locked.
- The builder is WSL-aware and converts paths for the Windows virtualenv automatically, so prefer it even when working from WSL.
