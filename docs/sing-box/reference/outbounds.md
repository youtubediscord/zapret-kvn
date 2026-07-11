# Outbound -- справочник полей

Целевая версия: sing-box 1.14.x

Ниже подробно документирован исторический конвертируемый набор: vless, vmess,
trojan, shadowsocks, socks, http, direct, block. Hysteria, Hysteria2 и TUIC
импортируются как native sing-box outbounds; остальные типы sing-box extended
можно импортировать объектом `{"type": ...}` без преобразования в Xray JSON.

---

## vless

### Структура

```json
{
  "type": "vless",
  "tag": "vless-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "flow": "",
  "network": "tcp",
  "packet_encoding": "xudp",
  "tls": {},
  "transport": {},
  "multiplex": {}
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес сервера | IP или домен |
| `server_port` | number | да | Порт сервера | 1-65535 |
| `uuid` | string | да | UUID пользователя VLESS | формат UUID |
| `flow` | string | нет | Суб-протокол VLESS | `xtls-rprx-vision` -- только с TLS/Reality, несовместим с transport |
| `network` | string | нет | Разрешённые протоколы | `tcp`, `udp`. По умолчанию оба |
| `packet_encoding` | string | нет | Кодирование UDP-пакетов | `xudp` (по умолчанию), `packetaddr` (v2ray 5+), пустая строка -- отключено |
| `tls` | object | нет | Настройки TLS | -> [TLS](./tls.md) |
| `transport` | object | нет | V2Ray Transport | -> [Transport](./transport.md) |
| `multiplex` | object | нет | Мультиплексирование | -> [Multiplex](./multiplex.md) |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

### Пример

```json
{
  "type": "vless",
  "tag": "vless-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "flow": "xtls-rprx-vision",
  "packet_encoding": "xudp",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

---

## vmess

### Структура

```json
{
  "type": "vmess",
  "tag": "vmess-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "security": "auto",
  "alter_id": 0,
  "global_padding": false,
  "authenticated_length": true,
  "network": "tcp",
  "packet_encoding": "xudp",
  "tls": {},
  "transport": {},
  "multiplex": {}
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес сервера | IP или домен |
| `server_port` | number | да | Порт сервера | 1-65535 |
| `uuid` | string | да | UUID пользователя VMess | формат UUID |
| `security` | string | нет | Метод шифрования | см. таблицу ниже. По умолчанию `auto` |
| `alter_id` | number | нет | Alter ID | см. таблицу ниже. По умолчанию `0` |
| `global_padding` | bool | нет | Случайное заполнение (тратит трафик; в v2ray включено принудительно) | По умолчанию `false` |
| `authenticated_length` | bool | нет | Шифрование блоков длины | По умолчанию `true` |
| `network` | string | нет | Разрешённые протоколы | `tcp`, `udp`. По умолчанию оба |
| `packet_encoding` | string | нет | Кодирование UDP-пакетов | `xudp` (xray), `packetaddr` (v2ray 5+), пустая строка -- отключено |
| `tls` | object | нет | Настройки TLS | -> [TLS](./tls.md) |
| `transport` | object | нет | V2Ray Transport | -> [Transport](./transport.md) |
| `multiplex` | object | нет | Мультиплексирование | -> [Multiplex](./multiplex.md) |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

**Таблица security:**

| Значение | Описание |
|----------|----------|
| `auto` | Автоматический выбор (по умолчанию) |
| `none` | Без шифрования |
| `zero` | Без шифрования, без аутентификации |
| `aes-128-gcm` | AES-128-GCM |
| `chacha20-poly1305` | ChaCha20-Poly1305 |
| `aes-128-ctr` | Legacy, не рекомендуется |

**Таблица alter_id:**

| Alter ID | Описание |
|----------|----------|
| `0` | Протокол AEAD (рекомендуется) |
| `1` | Legacy-протокол |
| `> 1` | Не используется, эквивалентно 1 |

### Пример

```json
{
  "type": "vmess",
  "tag": "vmess-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "security": "auto",
  "alter_id": 0,
  "authenticated_length": true,
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  },
  "transport": {
    "type": "ws",
    "path": "/ws"
  }
}
```

---

## trojan

### Структура

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "example.com",
  "server_port": 443,
  "password": "my-secret-password",
  "network": "tcp",
  "tls": {},
  "transport": {},
  "multiplex": {}
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес сервера | IP или домен |
| `server_port` | number | да | Порт сервера | 1-65535 |
| `password` | string | да | Пароль Trojan | строка |
| `network` | string | нет | Разрешённые протоколы | `tcp`, `udp`. По умолчанию оба |
| `tls` | object | нет | Настройки TLS | -> [TLS](./tls.md) |
| `transport` | object | нет | V2Ray Transport | -> [Transport](./transport.md) |
| `multiplex` | object | нет | Мультиплексирование | -> [Multiplex](./multiplex.md) |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

> **Важно:** протокол Trojan требует TLS. Без `tls.enabled: true` соединение не будет работать корректно.

### Пример

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "example.com",
  "server_port": 443,
  "password": "my-secret-password",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

---

## shadowsocks

### Структура

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "example.com",
  "server_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "base64-encoded-key",
  "plugin": "",
  "plugin_opts": "",
  "network": "tcp",
  "udp_over_tcp": false,
  "multiplex": {}
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес сервера | IP или домен |
| `server_port` | number | да | Порт сервера | 1-65535 |
| `method` | string | да | Метод шифрования | см. таблицу ниже |
| `password` | string | да | Пароль Shadowsocks | строка или base64-ключ (для 2022-методов) |
| `plugin` | string | нет | SIP003-плагин | `obfs-local`, `v2ray-plugin` |
| `plugin_opts` | string | нет | Параметры плагина | строка параметров |
| `network` | string | нет | Разрешённые протоколы | `tcp`, `udp`. По умолчанию оба |
| `udp_over_tcp` | bool / object | нет | UDP поверх TCP. Конфликтует с `multiplex` | По умолчанию `false` |
| `multiplex` | object | нет | Мультиплексирование. Конфликтует с `udp_over_tcp` | -> [Multiplex](./multiplex.md) |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

**Таблица method:**

| Категория | Метод |
|-----------|-------|
| Современные (2022) | `2022-blake3-aes-128-gcm` |
| | `2022-blake3-aes-256-gcm` |
| | `2022-blake3-chacha20-poly1305` |
| AEAD | `aes-128-gcm` |
| | `aes-192-gcm` |
| | `aes-256-gcm` |
| | `chacha20-ietf-poly1305` |
| | `xchacha20-ietf-poly1305` |
| Без шифрования | `none` |
| Legacy (не рекомендуются) | `aes-128-ctr` |
| | `aes-192-ctr` |
| | `aes-256-ctr` |
| | `aes-128-cfb` |
| | `aes-192-cfb` |
| | `aes-256-cfb` |
| | `rc4-md5` |
| | `chacha20-ietf` |
| | `xchacha20` |

### Пример

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "example.com",
  "server_port": 8388,
  "method": "2022-blake3-aes-256-gcm",
  "password": "8JCsPssfgS8tiRwiMlhARg=="
}
```

---

## socks

### Структура

```json
{
  "type": "socks",
  "tag": "socks-out",
  "server": "127.0.0.1",
  "server_port": 1080,
  "version": "5",
  "username": "",
  "password": "",
  "network": "tcp",
  "udp_over_tcp": false
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес сервера | IP или домен |
| `server_port` | number | да | Порт сервера | 1-65535 |
| `version` | string | нет | Версия SOCKS | `4`, `4a`, `5`. По умолчанию `5` |
| `username` | string | нет | Имя пользователя | строка |
| `password` | string | нет | Пароль (только SOCKS5) | строка |
| `network` | string | нет | Разрешённые протоколы | `tcp`, `udp`. По умолчанию оба |
| `udp_over_tcp` | bool / object | нет | UDP поверх TCP | По умолчанию `false` |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

> **Внимание (гибридный режим):** при использовании SOCKS outbound для relay-подключения
> (например, xray -> sing-box SOCKS) критически важно указать `inet4_bind_address: "127.0.0.1"`
> в Dial Fields, иначе соединение может не установиться.

### Пример

```json
{
  "type": "socks",
  "tag": "socks-relay",
  "server": "127.0.0.1",
  "server_port": 10808,
  "version": "5",
  "network": "tcp",
  "inet4_bind_address": "127.0.0.1"
}
```

---

## http

### Структура

```json
{
  "type": "http",
  "tag": "http-out",
  "server": "proxy.example.com",
  "server_port": 8080,
  "username": "",
  "password": "",
  "path": "",
  "headers": {},
  "tls": {}
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `server` | string | да | Адрес прокси-сервера | IP или домен |
| `server_port` | number | да | Порт прокси-сервера | 1-65535 |
| `username` | string | нет | Имя пользователя Basic-авторизации | строка |
| `password` | string | нет | Пароль Basic-авторизации | строка |
| `path` | string | нет | Путь HTTP-запроса | строка |
| `headers` | object | нет | Дополнительные HTTP-заголовки | `{"key": "value"}` |
| `tls` | object | нет | Настройки TLS (для HTTPS-прокси) | -> [TLS](./tls.md) |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

### Пример

```json
{
  "type": "http",
  "tag": "http-out",
  "server": "proxy.example.com",
  "server_port": 8080,
  "username": "user",
  "password": "pass"
}
```

---

## direct

### Структура

```json
{
  "type": "direct",
  "tag": "direct-out",
  "domain_resolver": "dns-local"
}
```

### Поля

| Поле | Тип | Обязательное | Описание | Значения / По умолчанию |
|------|-----|:---:|----------|-------------------------|
| `domain_resolver` | string / object | да (1.14+) | DNS-резолвер для доменных адресов | тег DNS-сервера (строка) или inline-объект |
| *Dial Fields* | | нет | Параметры подключения | -> [Dial Fields](./dial-fields.md) |

> **Важно (sing-box 1.14+):** поле `domain_resolver` обязательно для outbound-ов,
> которые обрабатывают доменные адреса. Без него sing-box вернёт ошибку при попытке
> разрешить домен через direct outbound.

### Пример

```json
{
  "type": "direct",
  "tag": "direct-out",
  "domain_resolver": "dns-local"
}
```

---

## block

### Структура

```json
{
  "type": "block",
  "tag": "block"
}
```

### Поля

Настраиваемых полей нет. Указываются только `type` и `tag`.

### Пример

```json
{
  "type": "block",
  "tag": "block"
}
```
