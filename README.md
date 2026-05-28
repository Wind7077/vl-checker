# vl-checker (RU edition)

Автоматический чекер прокси-конфигов с фокусом на обход российской блокировки.  
Запускается каждые 3 часа через GitHub Actions.

## Поддерживаемые протоколы

| Протокол | Описание |
|----------|----------|
| **VLESS + Reality** | Основной протокол, лучший обход ТСПУ |
| **Hysteria2** | UDP/QUIC, обходит DPI иначе чем TCP-протоколы |
| vmess, trojan, ss | Включаются через `ALLOWED_PROTOCOLS` в скрипте |

## Как добавить источники

Редактируй **`sources.yml`** в корне репозитория — добавляй URL в нужный раздел:

```yaml
custom:
  - url: "https://myserver.example/sub"
    label: "Мой приватный источник"
  - url: "https://example.com/configs.txt"
    label: "Ещё один источник"
    enabled: false  # временно отключить
```

Скрипт читает все секции (`russia_focused`, `aggregators`, `hysteria2`, `telegram_channels`, `custom`).

## Настройки в `scripts/check_proxies.py`

```python
ALLOWED_PROTOCOLS = ["vless", "hysteria2"]   # протоколы для проверки
REQUIRE_REALITY   = True                     # только VLESS+Reality
ALLOWED_COUNTRIES = set()                    # пусто = без геофильтра
TOP_N             = 80                       # сколько сохранять
```

## Результаты

| Файл | Описание |
|------|----------|
| [`output/proxies.txt`](output/proxies.txt) | Plain URI, один на строку |
| [`output/proxies_b64.txt`](output/proxies_b64.txt) | Base64 подписка для Karing / v2rayNG |
| [`output/report.json`](output/report.json) | Полный JSON с латентностями |

## Алгоритм проверки

```
sources.yml → fetch → extract_configs → filter_protocols
    → Stage1: TCP-ping (VLESS/etc) / DNS-resolve (Hysteria2)
    → geo_filter (опционально)
    → Stage2: xray-core SOCKS5 + curl (VLESS/vmess/trojan/ss)
             hysteria2-client SOCKS5 + curl (Hysteria2)
    → сортировка по HTTP-latency → сохранение top N
```

## Установка зависимостей

```bash
pip install aiohttp pyyaml
```

## Локальный запуск

```bash
python scripts/check_proxies.py
```
