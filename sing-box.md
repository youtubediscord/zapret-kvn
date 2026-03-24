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

## Рекомендация

1. **tun2socks по умолчанию** — стабильный, проверенный, работает с xhttp
2. **sing-box TUN как экспериментальная опция** — для process routing, требует доработки
3. Для sing-box TUN с xhttp нужна рабочая реализация dialerProxy или исправление direct outbound в будущих версиях sing-box

## Тестовая среда

- Windows 10 IoT Enterprise LTSC 2021 (build 19044)
- xray-core 26.2.6
- sing-box 1.13.3
- Транспорт: VLESS + xhttp + Reality
- Прокси сервер: 46.17.101.82:30443
