# XrayFluent — Handoff для нового AI

## Что это

PyQt6 + qfluentwidgets GUI клиент для xray/sing-box proxy с TUN VPN на Windows.
Репозиторий: `G:\bin\Xray-windows-64`

## Текущее состояние (2026-03-24)

### Работает:
- **sing-box TUN с dialerProxy** — process-based routing (маршрутизация по .exe файлам)
- **Process presets** — быстрый выбор: Telegram, Discord, Chrome, Firefox, Edge, Spotify, Torrents, Windows System/Defender/Update/OneDrive
- **Per-process traffic monitoring** — live таблица: скорость, VPN/Direct байты, хосты, соединения
- **Traffic history** — persistent JSON (`data/traffic_history.json`), sessions + daily totals
- **DNS settings** — configurable bootstrap/proxy DNS серверы и протоколы
- **Proxy ports в TUN mode** — SOCKS5:10808 + HTTP:8080 доступны параллельно с TUN
- **Windows API process tracking** — в proxy mode (без TUN) через `GetExtendedTcpTable`

### Архитектура sing-box TUN (hybrid mode):
```
App → TUN (sing-box) → process_name rules → proxy/direct
  proxy → SOCKS:11808 → xray → dialerProxy → SS protect (chacha20) → sing-box direct → VPS
  direct → sing-box direct → physical NIC → internet
```

### Ключевые файлы:
- `xray_fluent/singbox_config_builder.py` — генерация sing-box + xray конфигов
- `xray_fluent/app_controller.py` — центральный контроллер (подключение, hot-swap, метрики)
- `xray_fluent/process_traffic_collector.py` — Clash API polling, per-process stats
- `xray_fluent/win_proc_monitor.py` — Windows API для proxy mode
- `xray_fluent/traffic_history.py` — persistent storage сессий
- `xray_fluent/process_presets.py` — пресеты приложений
- `xray_fluent/ui/dashboard_page.py` — дашборд с графиком и таблицей процессов
- `xray_fluent/ui/routing_page.py` — настройки маршрутизации, DNS, process presets
- `sing-box.md` — полная документация: 5 попыток, баги, решения, справочник

### Известные ограничения:
- `strict_route: false` обязательно (true ломает direct outbound на Windows)
- `method:none` SS несовместим между xray и sing-box → используем chacha20-ietf-poly1305
- Запрет (DPI bypass) несовместим с sing-box sniff
- sing-box 1.14+ обязателен (1.13.3 имеет баг direct outbound)
- DNS: `outbound` rule items deprecated в 1.12, удалены в 1.14 → используем `domain_resolver`
- Per-process bytes недоступны в proxy mode (только connection count через Windows API)

### Что нужно доделать:
- [ ] UI страница истории трафика (фильтр по дням/месяцам, графики)
- [ ] Автоостановка запрета при включении TUN
- [ ] Баг: VPN отключается при смене настроек маршрутизации (reconnect race)
- [ ] Подстраница процессов: live обновление данных
- [ ] TUN + system proxy одновременно (сейчас proxy отключается при TUN)

### Сборка:
```bash
# Kill processes first!
wmic process where "name='XrayFluent.exe'" call terminate
wmic process where "name='xray.exe'" call terminate
wmic process where "name='sing-box.exe'" call terminate
sleep 5
.venv/Scripts/python build.py
```

### Правила (из CLAUDE.md):
- Используй stock qfluentwidgets компоненты
- Держи page surfaces transparent для Mica эффекта
- Hot-swap через `QTimer.singleShot(0, ...)`
- `_active_core` устанавливать ДО старта процессов
- Metrics worker стартовать только когда `_switching=False`
- sing-box log level: warn (не debug/info в production)
