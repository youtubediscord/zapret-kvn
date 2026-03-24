# sing-box TUN на Windows: проблемы и попытки

## Цель

Заменить tun2socks на sing-box TUN для поддержки маршрутизации по процессам (`process_name`).
tun2socks перехватывает весь трафик и пересылает на xray SOCKS — xray видит все соединения от `tun2socks.exe`, определение процесса невозможно.

## Хронология попыток

### Попытка 1: SOCKS bridge (sing-box TUN → SOCKS → xray)

**Архитектура:**
```
App → TUN (sing-box) → SOCKS:11808 → xray → xhttp → VPS
xray.exe bypass через process_name → direct
```

**Проблемы найденные и исправленные:**
1. `sniff` / `sniff_override_destination` в TUN inbound — **удалены в sing-box 1.13.0**. Мигрировано на `{"action": "sniff"}` в route rules.
2. `auto_detect_interface` ломает SOCKS → localhost — bind к физическому NIC вместо loopback. Исправлено через `inet4_bind_address: "127.0.0.1"`.
3. Нет `hijack-dns` в hybrid config — DNS не перехватывался. Добавлено.
4. Нет sniffing на xray SOCKS inbound — xray не видел домены, domain routing не работал. Добавлен sniffing с `routeOnly: true`.

**Результат:** Частично работало ("вроде работает"). Но:
- Много ошибок xhttp (connection upload closed) — нормальное поведение xhttp транспорта
- claude.exe (node.js) не работал через TUN — DNS через proxy chain (DoH → SOCKS → xray → xhttp) слишком медленный
- `process_name: xray.exe → direct` — хрупкий механизм

### Попытка 2: DNS через direct (без detour)

Сменили DNS на `{"type": "udp", "server": "8.8.8.8"}` без `detour`.

**Проблема:** `FATAL: start dns/udp[direct-dns]: detour to an empty direct outbound makes no sense` — sing-box 1.13 отвергает detour к пустому direct outbound.

Убрали detour полностью → DNS пакеты идут через OS default route → TUN → hijack-dns → DNS module → снова к 8.8.8.8 → **ROUTING LOOP** (700+ connections/sec).

### Попытка 3: dialerProxy (v2rayN-style архитектура)

**Архитектура:**
```
App → TUN (sing-box) → SS(chacha20):PORT_A → xray → xhttp → VPS
xray outbound → dialerProxy → SS:PORT_B → sing-box tun-protect → direct
```

**Проблемы:**
1. `method: "none"` несовместим между sing-box 1.13 и xray 26.2 — `failed to read 50 bytes`. Сменили на `chacha20-ietf-poly1305`.
2. **sing-box direct outbound НЕ МОЖЕТ выйти в интернет** когда TUN активен (даже для трафика от tun-protect inbound):
   - `auto_detect_interface: true` — не работает
   - `default_interface: "Ethernet"` — не работает
   - `stack: "system"` — не работает
   - `stack: "mixed"` — не работает
   - Все попытки подключения через direct outbound дают `i/o timeout`
   - Это значит трафик из tun-protect inbound → direct outbound → ловится TUN обратно → loop

**Вывод:** dialerProxy архитектура невозможна на данной системе из-за бага sing-box direct outbound на Windows.

### Попытка 4: Возврат на SOCKS bridge + TCP DNS через proxy

Вернулись на SOCKS bridge. DNS: `{"type": "tcp", "server": "8.8.8.8", "detour": "proxy"}` — TCP DNS через SOCKS → xray → xray резолвит.

**Результат:** Тот же routing loop (700+ connections/sec). `5.28.195.2:443 via outbound/direct[direct]: i/o timeout`. Даже `192.168.1.180:80 via direct: i/o timeout` — LAN тоже недоступен. DNS fix не помог — проблема не в DNS, а в sing-box direct outbound на этом Windows.

### Итоговый вердикт

**sing-box direct outbound сломан на Windows 10 IoT LTSC 2021 (build 19044)** с sing-box 1.13.3. Ни одна из попыток (auto_detect_interface, default_interface, stack types, DNS strategies) не решила routing loop. Проблема фундаментальная: direct outbound не может отправить трафик через физический NIC когда TUN активен — трафик ловится TUN обратно и зацикливается.

**Решение:** tun2socks по умолчанию + sing-box как экспериментальная опция.

## Ключевые проблемы sing-box на Windows

### 1. direct outbound не работает для non-TUN inbound трафика
Когда трафик приходит через SS/SOCKS inbound (не TUN), direct outbound не может отправить его в интернет — `auto_detect_interface` не привязывает сокет к физическому NIC. Трафик ловится TUN и зацикливается.

**Но**: direct outbound РАБОТАЕТ для трафика из TUN inbound с `process_name` match (xray.exe → direct). Причина неясна — возможно разный code path в sing-box для TUN-initiated vs inbound-initiated connections.

### 2. DNS routing loop
Без `detour` на DNS сервере: DNS пакеты → TUN → hijack-dns → DNS module → отправка к DNS серверу → TUN → loop. Нужен обязательный `detour: "proxy"` для DNS.

### 3. Deprecated/removed поля в 1.13
- `sniff`, `sniff_override_destination` в TUN inbound удалены. Нужны route rule actions.
- `detour` к пустому direct outbound запрещён.

### 4. SS method "none" несовместимость
`method: "none"` между sing-box 1.13 и xray 26.2 даёт `failed to read 50 bytes`. Нужен реальный cipher (chacha20-ietf-poly1305).

### 5. Нестабильность xhttp через double-proxy
Цепочка TUN → SOCKS → xray → xhttp → VPS нестабильна. xhttp создаёт множество параллельных стримов, часть обрывается. Для приложений с агрессивным timeout (node.js/claude) это критично.

## Сравнение tun2socks vs sing-box TUN

| Фича | tun2socks | sing-box TUN |
|------|-----------|--------------|
| Стабильность | Высокая | Низкая (Windows) |
| Process routing | Нет | Да (process_name) |
| DNS routing | Нет (xray handles) | Проблемная (loop risks) |
| Routing loop prevention | Маршруты через netsh | process_name / dialerProxy (не работает) |
| Совместимость с xhttp | Хорошая (прямой SOCKS) | Проблемная (double-proxy) |
| Настройка | Простая | Сложная (много подводных камней) |

### Попытка 5: dialerProxy с sing-box 1.14.0-alpha.5 (2026-03-24)

**Предпосылки:**
- Анализ исходного кода v2rayN показал архитектуру "protect SS канала" через `dialerProxy`
- Скачан sing-box 1.14.0-alpha.5 (pre-built binary)
- Цель: проверить исправлен ли баг SS inbound → direct outbound (не работал на 1.13.3)

**Архитектура v2rayN (эталон):**
```
App → TUN (sing-box) → relay outbound → xray SOCKS inbound
xray → proxy outbound → dialerProxy → "tun-protect-out" SS outbound → sing-box SS inbound → direct → internet
process_name: [xray.exe, sing-box.exe] → direct (защита от routing loop)
```

**Тест 1: SS inbound → direct outbound (chacha20-ietf-poly1305)**

Конфиг sing-box:
```json
{
  "inbounds": [
    {"type": "tun", "tag": "tun-in", "interface_name": "test_tun",
     "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true, "stack": "mixed"},
    {"type": "shadowsocks", "tag": "tun-protect", "listen": "127.0.0.1",
     "listen_port": 19200, "method": "chacha20-ietf-poly1305", "password": "testpassword123"}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {"action": "sniff"},
      {"process_name": ["sing-box.exe"], "outbound": "direct"},
      {"inbound": ["tun-protect"], "outbound": "direct"},
      {"ip_is_private": true, "outbound": "direct"}
    ]
  }
}
```

Конфиг xray (SS outbound → sing-box SS inbound):
```json
{
  "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": 11808,
    "settings": {"auth": "noauth", "udp": true}}],
  "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [
    {"address": "127.0.0.1", "port": 19200, "method": "chacha20-ietf-poly1305", "password": "testpassword123"}
  ]}}]
}
```

Тест:
```bash
curl -x socks5h://127.0.0.1:11808 http://httpbin.org/ip
# Результат: {"origin": "109.252.184.208"}
```

**РЕЗУЛЬТАТ: ✅ РАБОТАЕТ!** SS inbound → direct outbound на sing-box 1.14.0-alpha.5 **исправлен**.
IP 109.252.184.208 — реальный IP провайдера (не proxy), трафик выходит через physical NIC минуя TUN.

**Тест 2: method:none совместимость (xray 26.2 ↔ sing-box 1.14)**

Тот же тест, но с `"method": "none", "password": ""` на обеих сторонах.

```bash
curl -x socks5h://127.0.0.1:11808 http://httpbin.org/ip
# Результат: curl: (7) Failed to connect to httpbin.org port 80 via 127.0.0.1 after 2036 ms
```

**РЕЗУЛЬТАТ: ❌ НЕ РАБОТАЕТ.** Баг `method:none` между xray и sing-box по-прежнему присутствует.
Тот же симптом что в Попытке 3 — xray отправляет пакет, sing-box не может его прочитать.

**Вывод:**
- **Баг direct outbound для inbound-initiated трафика ИСПРАВЛЕН в sing-box 1.14** (не работал на 1.13.3)
- `method:none` по-прежнему сломан между xray и sing-box — используем `chacha20-ietf-poly1305`
- Overhead шифрования на localhost пренебрежимо мал
- Архитектура v2rayN с dialerProxy + protect SS каналом теперь реализуема

**Тест 3: интеграция в приложение — первый запуск**

Ошибка sing-box 1.14 при старте:
```
FATAL: outbound DNS rule item is deprecated in sing-box 1.12.0 and will be removed in sing-box 1.14.0
```

**Причина:** DNS rule `{"outbound": ["direct"], "server": "bootstrap-dns"}` — deprecated в 1.12, удалён в 1.14.
Этот формат позволял назначить DNS сервер для outbound'а через DNS rules. В 1.14 нужно использовать `domain_resolver` прямо на outbound'е.

**Фикс:**
```diff
- "dns": { "rules": [{"outbound": ["direct"], "server": "bootstrap-dns"}] }
+ // Вместо DNS rule — field на самом outbound:
+ direct_out = {"type": "direct", "tag": "direct", "domain_resolver": "bootstrap-dns"}
+ // + default_domain_resolver в route:
+ "route": { "default_domain_resolver": "proxy-dns", ... }
```

**ВАЖНО для совместимости с sing-box 1.14+:**
- НЕ использовать `outbound` как match condition в DNS rules
- Использовать `domain_resolver` field на outbound'ах
- Использовать `default_domain_resolver` в route config

**Тест 4: полная интеграция в приложение (после фиксов)**

После исправления 3 багов:
1. `outbound` DNS rule → заменён на `domain_resolver` на outbound'ах
2. outbound tag `relay` → `proxy` (совпадает с routing rules)
3. Убран debug лог

**РЕЗУЛЬТАТ: ✅ РАБОТАЕТ!** Полная цепочка dialerProxy подтверждена:
- `outbound/socks[proxy]` — весь трафик приложений идёт через proxy
- protect канал: `tun-protect → 46.17.101.82:30443 → direct` — xray достигает VPS
- TLS sniff: определяет домены из SNI → domain routing работает
- DNS hijack: перехватывает DNS → proxy-dns через TCP
- QUIC sniff: определяет QUIC → routing по доменам
- Telegram (AyuGram.exe): подключается через proxy, сообщения ходят

**Тест 5: process routing — default=direct + Telegram.exe→proxy**

Конфиг: `tun_default_outbound = "direct"`, process rule `Telegram.exe → proxy`.

**РЕЗУЛЬТАТ: ✅ РАБОТАЕТ!** Telegram идёт через VPN, остальной трафик напрямую.

**Итого подтверждённые режимы:**
- Default=proxy (весь трафик через VPN) ✅
- Default=direct + exe→proxy (только выбранные приложения через VPN) ✅
- Process routing по exe файлам ✅
- Protect канал (dialerProxy + SS chacha20) ✅

**Ключевые баги при интеграции (исправлены):**
1. `outbound` DNS rule deprecated в sing-box 1.12, удалён в 1.14 → FATAL при старте. Фикс: `domain_resolver` на outbound'ах
2. outbound tag mismatch: routing rules генерируют `outbound: "proxy"`, а outbound назывался `"relay"` → `outbound not found: proxy`. Фикс: переименовать в `"proxy"`
3. Google service routes (`google.com → direct`) потенциально перехватывают Telegram MTProto (фейковый TLS SNI)

**Известные ограничения:**
4. **Запрет (DPI bypass) + sing-box sniff несовместимы.** Запрет фрагментирует TLS ClientHello → sing-box sniff не может определить SNI/протокол → routing застревает на sniff action → соединение таймаутит. **Решение:** отключить запрет при использовании sing-box TUN (VPN и так обходит DPI).

---

## Рекомендация (обновлено 2026-03-24)

1. **tun2socks по умолчанию** — стабильный, проверенный, работает с xhttp
2. **sing-box TUN с dialerProxy** — теперь рабочий на sing-box ≥ 1.14, поддерживает process routing
3. Обязательно: sing-box 1.14+ (1.13.3 имеет баг direct outbound для inbound-initiated трафика)
4. Protect канал: `chacha20-ietf-poly1305` (method:none сломан между xray и sing-box)
5. **НЕ использовать** `outbound` DNS rule items — deprecated в 1.12, удалены в 1.14. Вместо этого: `domain_resolver` на outbound'ах

---

## Справочник: правильная работа с sing-box TUN на Windows

### Архитектура (hybrid mode для xhttp)

```
App traffic → TUN (sing-box) → process_name rules → proxy/direct
  ├─ proxy → SOCKS:11808 → xray → dialerProxy → SS protect → sing-box direct → VPS
  └─ direct → sing-box direct outbound → physical NIC → internet

xray.exe, sing-box.exe → process_name → direct (защита от routing loop)
tun-protect inbound → direct (protect канал)
```

### Обязательные настройки sing-box TUN

```json
{
  "type": "tun",
  "auto_route": true,
  "strict_route": false,     // true ломает direct outbound на Windows!
  "stack": "mixed"            // system или mixed, НЕ gvisor
}
```

### DNS конфигурация

**Два DNS сервера обязательны:**
- `bootstrap-dns` — UDP, без detour, для direct трафика (resolve доменов при direct outbound)
- `proxy-dns` — TCP/HTTPS/TLS через proxy detour, для proxy трафика

```json
"dns": {
  "servers": [
    {"tag": "bootstrap-dns", "type": "udp", "server": "1.1.1.1"},
    {"tag": "proxy-dns", "type": "tcp", "server": "8.8.8.8", "detour": "proxy"}
  ],
  "final": "proxy-dns"
}
```

**`domain_resolver` на outbound'ах (sing-box 1.14+):**
- direct outbound: `"domain_resolver": "bootstrap-dns"`
- proxy outbound: `"domain_resolver": "proxy-dns"`
- route: `"default_domain_resolver": "proxy-dns"`

**НЕ использовать:** `{"outbound": ["direct"], "server": "bootstrap-dns"}` в dns.rules — deprecated в 1.12, удалён в 1.14.

**Доступные типы DNS:** `udp`, `tcp`, `tls` (DoT), `https` (DoH), `quic` (DoQ).
**Доступные серверы:** 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9), 208.67.222.222 (OpenDNS).

### Protect канал (dialerProxy)

```
xray proxy outbound → dialerProxy:"tun-protect-out"
  → SS outbound (chacha20-ietf-poly1305, random password, port 19200-19300)
  → sing-box SS inbound "tun-protect"
  → direct outbound → physical NIC → VPS
```

- **method:none НЕ совместим** между xray и sing-box — используем chacha20-ietf-poly1305
- Пароль генерируется случайно при каждом подключении
- Hot-swap: при смене ноды перезапускается только xray, sing-box TUN остаётся

### Process routing правила

**Порядок rules (важен!):**
1. `sniff` — определить протокол/домен из TLS SNI
2. `hijack-dns` — перехватить DNS пакеты
3. Protected processes → direct (xray.exe, sing-box.exe, tun2socks.exe)
4. `tun-protect` inbound → direct
5. `ip_is_private` → direct (LAN bypass)
6. Service domain routes (YouTube, Discord, etc.)
7. User domain rules
8. **Process presets** (Telegram→proxy, Windows system→direct)
9. User manual process rules
10. `route.final` — default outbound (proxy или direct)

### Известные проблемы и ограничения

1. **strict_route: true** ломает direct outbound на Windows — WFP перехватывает даже трафик от sing-box.exe
2. **method:none** сломан между xray 26.2 и sing-box 1.14 — используем chacha20
3. **Запрет (DPI bypass)** несовместим с sing-box sniff — фрагментация TLS ClientHello мешает определить SNI
4. **sing-box 1.13.3** имеет баг direct outbound для inbound-initiated трафика (исправлен в 1.14)
5. **Google service routes** (google.com→direct) могут перехватить Telegram MTProto (фейковый TLS SNI)
6. **Per-process stats** доступны только через Clash API `GET /connections` (sing-box TUN mode)

### Clash API endpoints

- `GET /connections` — per-connection данные: processPath, upload, download, chains, rule
- `GET /proxies` — список outbound'ов (без traffic stats)
- `GET /rules` — активные правила

## Тестовая среда

- Windows 10 IoT Enterprise LTSC 2021 (build 19044)
- xray-core 26.2.6
- sing-box 1.13.3 → **1.14.0-alpha.5** (обновлено)
- Транспорт: VLESS + xhttp + Reality
- Прокси сервер: 46.17.101.82:30443
