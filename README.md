# 🛡️ Proxy Checker

Автоматически проверяет VLESS/VMess/Trojan прокси из открытых источников каждые 3 часа.  
Оставляет **топ 100 самых быстрых** рабочих конфигов.

## 📥 Как использовать результаты

| Файл | Ссылка | Для чего |
|------|--------|----------|
| `output/proxies.txt` | [открыть](output/proxies.txt) | v2rayN, Nekobox — импорт из файла |
| `output/proxies_b64.txt` | [открыть](output/proxies_b64.txt) | Shadowrocket, v2rayNG — ссылка на подписку |
| `output/report.json` | [открыть](output/report.json) | полный отчёт с латентностью |

> **Подписка обновляется автоматически** — просто добавьте raw-ссылку на `proxies_b64.txt`  
> в своё приложение один раз, и оно будет тянуть свежие конфиги само.

### Raw URL для подписки

```
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/output/proxies_b64.txt
```

*(замените `YOUR_USERNAME` и `YOUR_REPO` на свои)*

---

## ⚙️ Как работает

```
GitHub Actions (каждые 3 часа)
        │
        ▼
scripts/check_proxies.py
        │
        ├─ Скачивает конфиги из 5 источников
        ├─ Декодирует base64-подписки
        ├─ TCP-пинг каждого хоста (до 120 одновременно)
        ├─ Сортирует по латентности
        └─ Сохраняет топ 100 в output/
        │
        ▼
git commit & push → файлы обновлены
```

### Источники

- `zieng2/wl` — vless_universal
- `whoahaow/rjsxrd` — bypass-all
- `key.zarazaex.xyz/sub` — подписка
- `Wind7077/vl-auto` — vless_normal_vpn
- `igareck/vpn-configs-for-russia` — Vless-Reality для РФ

---

## 🚀 Деплой (fork & run)

1. **Fork** этого репозитория
2. **Settings → Actions → General** → убедитесь что Actions включены
3. **Actions → Proxy Checker → Run workflow** — первый запуск вручную
4. Дальше запускается сам каждые 3 часа

> Никаких секретов и токенов не нужно — `GITHUB_TOKEN` встроен в Actions.

---

## 📱 Рекомендуемые клиенты

| Платформа | Приложение |
|-----------|-----------|
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) / [Hiddify](https://github.com/hiddify/hiddify-next) |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) / [Streisand](https://apps.apple.com/app/streisand/id6450534064) |
| Windows | [v2rayN](https://github.com/2dust/v2rayN) / [Hiddify](https://github.com/hiddify/hiddify-next) |
| Linux/Mac | [Hiddify](https://github.com/hiddify/hiddify-next) / [Nekobox](https://github.com/MatsuriDayo/nekoray) |

---

*Обновляется автоматически каждые 3 часа*
