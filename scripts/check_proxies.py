#!/usr/bin/env python3
"""
Proxy Checker — RU edition
──────────────────────────
Пайплайн:
  sources.txt
    → fetch (async, все источники параллельно)
    → extract + deduplicate
    → protocol/reality filter
    → Stage 1: TCP-ping (vless/vmess/trojan/ss) / DNS-resolve (hysteria2)
    → geo filter (опционально)
    → Stage 2: поднимаем xray/hysteria2 как SOCKS5, делаем curl
               через ВСЕ probe-URL → считаем reliability
    → Scoring: взвешенная сумма tcp + http + бонус за надёжность + бонус протокола
    → Top N → proxies.txt / proxies_b64.txt / report.json / README.md
"""

import asyncio
import aiohttp
import base64
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
# НАСТРОЙКИ — меняй здесь
# ══════════════════════════════════════════════════════════════════════════════

# Какие протоколы проверять. Убери лишние или добавь "vmess","trojan","ss"
ALLOWED_PROTOCOLS = ["vless", "hysteria2"]

# True  = vless только с reality (лучший обход ТСПУ)
# False = любой vless
REQUIRE_REALITY = True

# Геофильтр — пусто = без ограничений. Пример: {"NL","DE","EE","FI","AM","GE"}
ALLOWED_COUNTRIES: set[str] = set()

# Сколько лучших прокси сохранять в итоге
TOP_N = 250

# Сколько TCP-alive кандидатов передавать в Stage 2 (тяжёлую проверку)
STAGE2_CANDIDATES = 600

# Параллелизм
MAX_CONCURRENT_TCP  = 200   # Stage 1: TCP-пинги
MAX_CONCURRENT_HTTP = 20    # Stage 2: xray/hy2 процессы одновременно

# Таймауты (секунды)
TIMEOUT_TCP        = 3
TIMEOUT_CURL       = 10
TIMEOUT_XRAY_START = 1.0   # пауза после запуска xray перед curl
TIMEOUT_HY2_START  = 1.5   # hysteria2 стартует чуть дольше

# ── Scoring ───────────────────────────────────────────────────────────────────
# score = TCP_W * tcp_ms + HTTP_W * avg_http_ms
#         - RELIABILITY_BONUS * (успешных_probe - 1)
#         - PROTO_BONUS[proto]
# Меньше score = лучше. Сортируем по score.
TCP_W             = 0.3
HTTP_W            = 1.0
RELIABILITY_BONUS = 300   # за каждый дополнительный успешный probe-URL
PROTO_BONUS: dict[str, int] = {
    "hysteria2": 100,  # чуть предпочитаем hysteria2 за UDP-природу
    "vless":     0,
}

# ── Probe-URL: ресурсы заблокированные в РФ ──────────────────────────────────
# Формат: (url, [допустимые HTTP-коды])
# Чем больше URL — тем точнее reliability, но дольше Stage 2
# Probe-URL выбраны так чтобы работать И с GitHub Actions (не блокируют),
# И являются индикаторами что прокси реально работает для РФ-пользователя.
# ip.sb / ifconfig.me просто возвращают IP прокси — это надёжный нейтральный тест.
# cp.cloudflare.com — глобальный CDN, 204 означает что прокси маршрутирует трафик.
PROBE_URLS = [
    ("https://cp.cloudflare.com/",   [200, 204]),   # Cloudflare connectivity check
    ("https://ip.sb/",               [200]),         # возвращает IP — нейтральный
    ("https://ifconfig.me/ip",       [200]),         # то же, резервный
]

GEO_BATCH_SIZE = 100  # ip-api.com batch limit

# ── Пути ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
REPO_ROOT    = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR   = REPO_ROOT / "output"

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN  = Path("/tmp/hysteria-bin/hysteria")

SOCKS_BASE_PORT = 20000


# ══════════════════════════════════════════════════════════════════════════════
# Загрузка sources.txt
# Формат: один URL на строку, # = комментарий, пустые строки пропускаются
# ══════════════════════════════════════════════════════════════════════════════

def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        print(f"  ⚠️  {SOURCES_FILE} не найден")
        return []
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    print(f"  📄 {len(urls)} источников из {SOURCES_FILE.name}")
    return urls


# ══════════════════════════════════════════════════════════════════════════════
# Вспомогательные функции
# ══════════════════════════════════════════════════════════════════════════════

def decode_b64(data: str) -> str:
    data = data.strip()
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="ignore")
    except Exception:
        return data


def extract_configs(text: str) -> list[str]:
    """Извлекает proxy URI из текста. Умеет раскодировать base64-обёртки."""
    stripped = text.strip()
    # Если весь файл — base64, декодируем
    if re.match(r'^[A-Za-z0-9+/\n\r=]{60,}$', stripped):
        decoded = decode_b64(stripped)
        protos = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")
        if any(p in decoded for p in protos):
            text = decoded
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")):
            result.append(line)
    return result


def filter_configs(configs: list[str]) -> list[str]:
    out = []
    for uri in configs:
        scheme = uri.split("://")[0].lower()
        if ALLOWED_PROTOCOLS and scheme not in ALLOWED_PROTOCOLS:
            continue
        if REQUIRE_REALITY and scheme == "vless" and "reality" not in uri.lower():
            continue
        out.append(uri)
    return out

# Нормализует параметры URL для дедупликации: сортирует query-параметры,
# убирает мусорные ключи (Telegram-реклама, host-реклама), чистит fragment.
_JUNK_PARAMS = {"telegram", "host", "path_junk"}  # lowercase ключи-мусор

def _canonical_key(uri: str) -> str:
    """
    Ключ дедупликации — только значимые части URI.
    Два конфига с одним UUID/pbk но разными IP/мусором → разные ключи (по IP).
    Два конфига с одним UUID/IP но разным мусором в fragment/Telegram= → один ключ.
    """
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        # Убираем мусорные параметры (реклама Telegram-каналов)
        clean = {
            k: v for k, v in params.items()
            if k.lower() not in ("telegram", "host_ad")
            and not v.startswith("Join")
            and not v.startswith("@")
            and "---" not in v
        }
        # Сортируем параметры для стабильного ключа
        q = urllib.parse.urlencode(sorted(clean.items()))
        # Fragment полностью игнорируем (там обычно название/латентность)
        return f"{scheme}://{p.username}@{p.hostname}:{p.port}?{q}"
    except Exception:
        return uri


def dedup_configs(configs: list[str]) -> list[str]:
    """Убирает дубликаты с разным мусором но одинаковой сутью."""
    seen: set[str] = set()
    result = []
    for uri in configs:
        key = _canonical_key(uri)
        if key not in seen:
            seen.add(key)
            result.append(uri)
    return result



def parse_host_port(uri: str) -> tuple[str, int, str] | None:
    """Возвращает (host, port, 'tcp'|'udp') или None."""
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        host, port = p.hostname, p.port
        if not host or not port:
            return None
        return host, port, ("udp" if scheme == "hysteria2" else "tcp")
    except Exception:
        return None


def compute_score(item: dict) -> float:
    """Меньше = лучше."""
    tcp  = item.get("tcp_ms") or 500          # hysteria2 не имеет tcp_ms
    http = item.get("http_ms") or 9999
    rel  = item.get("probe_ok", 1)
    proto = item.get("proto", "")
    score = TCP_W * tcp + HTTP_W * http
    score -= RELIABILITY_BONUS * max(0, rel - 1)
    score -= PROTO_BONUS.get(proto, 0)
    return round(score, 1)


# ══════════════════════════════════════════════════════════════════════════════
# Скачивание источников
# ══════════════════════════════════════════════════════════════════════════════

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    # Автоконверсия github.com/…/blob/… → raw
    url = re.sub(
        r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
        r'raw.githubusercontent.com/\1/\2/refs/heads/\3',
        url,
    )
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
            if resp.status == 200:
                text = await resp.text(encoding="utf-8", errors="ignore")
                configs = extract_configs(text)
                status = f"✓ {len(configs):4d} конфигов"
            else:
                configs = []
                status = f"✗ HTTP {resp.status}"
    except Exception as e:
        configs = []
        status = f"✗ {type(e).__name__}"
    short = url[:68]
    print(f"  {status}  {short}")
    return configs


# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: TCP-ping / DNS-resolve
# ══════════════════════════════════════════════════════════════════════════════

async def tcp_ping(host: str, port: int) -> float | None:
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TIMEOUT_TCP
        )
        ms = round((time.monotonic() - t0) * 1000, 1)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return ms
    except Exception:
        return None


async def stage1_worker(sem: asyncio.Semaphore, uri: str) -> dict | None:
    hp = parse_host_port(uri)
    if not hp:
        return None
    host, port, proto_type = hp
    proto = uri.split("://")[0].lower()

    async with sem:
        if proto_type == "udp":
            # Hysteria2 работает на UDP — TCP-пинг бесполезен.
            # Делаем DNS-resolve: если хост не резолвится, сервер точно мёртв.
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.getaddrinfo(host, port), timeout=TIMEOUT_TCP
                )
                return {"uri": uri, "host": host, "port": port,
                        "tcp_ms": None, "proto": proto}
            except Exception:
                return None
        else:
            ms = await tcp_ping(host, port)
            if ms is None:
                return None
            return {"uri": uri, "host": host, "port": port,
                    "tcp_ms": ms, "proto": proto}


# ══════════════════════════════════════════════════════════════════════════════
# Geo-фильтр (ip-api.com batch)
# ══════════════════════════════════════════════════════════════════════════════

async def geo_filter(items: list[dict]) -> list[dict]:
    if not ALLOWED_COUNTRIES:
        return items

    # Группируем по хосту — один запрос на уникальный хост
    hosts = list({x["host"] for x in items})
    print(f"  🌍 Geo lookup: {len(hosts)} уникальных хостов…")
    allowed: set[str] = set()

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as sess:
        for i in range(0, len(hosts), GEO_BATCH_SIZE):
            batch = hosts[i : i + GEO_BATCH_SIZE]
            payload = [{"query": h, "fields": "query,countryCode,status"} for h in batch]
            try:
                async with sess.post(
                    "http://ip-api.com/batch", json=payload,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as r:
                    if r.status == 200:
                        for e in await r.json(content_type=None):
                            if e.get("status") == "success" and \
                               e.get("countryCode") in ALLOWED_COUNTRIES:
                                allowed.add(e["query"])
            except Exception as e:
                print(f"  ⚠️  geo error: {e} — пропускаем партию")
                allowed.update(batch)   # при ошибке не режем
            await asyncio.sleep(0.5)

    result = [x for x in items if x["host"] in allowed]
    print(f"  ✅ Geo: {len(result)}/{len(items)} прошли фильтр")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Установка бинарей
# ══════════════════════════════════════════════════════════════════════════════

def _download(url: str, dest: Path) -> bool:
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  ✗ download error: {e}")
        return False


def install_xray() -> bool:
    if XRAY_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи xray.exe в {XRAY_BIN}")
        return False
    print("  📦 Downloading xray-core…")
    arch  = platform.machine().lower()
    fname = "Xray-linux-arm64-v8a.zip" if arch in ("aarch64", "arm64") else "Xray-linux-64.zip"
    url   = f"https://github.com/XTLS/Xray-core/releases/latest/download/{fname}"
    tmp   = Path("/tmp/xray.zip")
    if not _download(url, tmp):
        return False
    try:
        with zipfile.ZipFile(tmp) as z:
            z.extractall(XRAY_BIN.parent)
        XRAY_BIN.chmod(0o755)
        print("  ✓ xray-core ready")
        return True
    except Exception as e:
        print(f"  ✗ xray unzip: {e}")
        return False


def install_hysteria2() -> bool:
    if HY2_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи hysteria.exe в {HY2_BIN}")
        return False
    print("  📦 Downloading hysteria2…")
    arch  = platform.machine().lower()
    fname = "hysteria-linux-arm64" if arch in ("aarch64", "arm64") else "hysteria-linux-amd64"
    url   = f"https://github.com/apernet/hysteria/releases/latest/download/{fname}"
    if not _download(url, HY2_BIN):
        return False
    HY2_BIN.chmod(0o755)
    print("  ✓ hysteria2 ready")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: curl через SOCKS5
# Ключевое: пробуем ВСЕ probe-URL и считаем reliability
# ══════════════════════════════════════════════════════════════════════════════

async def curl_one(socks_port: int, url: str, ok_codes: list[int]) -> float | None:
    """Один curl-запрос. Возвращает латентность мс или None."""
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null",
            "--socks5-hostname", f"127.0.0.1:{socks_port}",
            "--max-time", str(TIMEOUT_CURL),
            "--connect-timeout", "5",
            "-w", "%{http_code}",
            "--insecure", "-L",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            url,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_CURL + 3)
        code = int(stdout.decode().strip() or "0")
        if code in ok_codes:
            return round((time.monotonic() - t0) * 1000, 1)
    except Exception:
        pass
    return None


async def curl_probe_all(socks_port: int) -> tuple[float | None, int]:
    """
    Пробует все PROBE_URLS через данный SOCKS5-порт.
    Возвращает (средняя_латентность_успешных, кол-во_успехов).
    probe_ok >= 1 → прокси рабочий.
    probe_ok == len(PROBE_URLS) → максимальная надёжность.
    """
    lats = []
    for url, ok_codes in PROBE_URLS:
        ms = await curl_one(socks_port, url, ok_codes)
        if ms is not None:
            lats.append(ms)
    if not lats:
        return None, 0
    return round(sum(lats) / len(lats), 1), len(lats)


# ── Построение xray-конфига ───────────────────────────────────────────────────

def make_xray_config(uri: str, socks_port: int) -> dict | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vless":
            p      = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            host   = p.hostname or ""
            port   = p.port or 443
            net    = params.get("type", "tcp")
            sec    = params.get("security", "none")
            sni    = params.get("sni", params.get("peer", host))
            ob = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{
                    "id": p.username or "",
                    "encryption": "none",
                    "flow": params.get("flow", ""),
                }]}]},
                "streamSettings": {"network": net},
            }
            ss = ob["streamSettings"]
            if sec == "reality":
                ss["security"] = "reality"
                ss["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", ""),
                }
            elif sec == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {
                    "serverName": sni,
                    "fingerprint": params.get("fp", "chrome"),
                    "allowInsecure": True,
                }
            if net == "ws":
                ss["wsSettings"] = {
                    "path": params.get("path", "/"),
                    "headers": {"Host": params.get("host", host)},
                }
            elif net == "grpc":
                ss["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

        elif scheme == "trojan":
            p      = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            host   = p.hostname or ""
            port   = p.port or 443
            ob = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port,
                                           "password": p.username or ""}]},
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": {"serverName": params.get("sni", host),
                                    "allowInsecure": True},
                },
            }

        elif scheme == "vmess":
            cfg  = json.loads(decode_b64(uri[len("vmess://"):]))
            host = cfg.get("add", "")
            port = int(cfg.get("port", 443))
            net  = cfg.get("net", "tcp")
            sni  = cfg.get("sni", cfg.get("host", host))
            ob = {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{
                    "id": cfg.get("id", ""),
                    "alterId": int(cfg.get("aid", 0)),
                    "security": "auto",
                }]}]},
                "streamSettings": {"network": net},
            }
            ss = ob["streamSettings"]
            if cfg.get("tls") == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
            if net == "ws":
                ss["wsSettings"] = {
                    "path": cfg.get("path", "/"),
                    "headers": {"Host": cfg.get("host", host)},
                }

        elif scheme == "ss":
            p  = urllib.parse.urlparse(uri)
            ui = p.username or ""
            if ":" not in ui:
                ui = decode_b64(ui)
            method, password = ui.split(":", 1)
            ob = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": p.hostname or "",
                                           "port": p.port or 443,
                                           "method": method,
                                           "password": password}]},
                "streamSettings": {"network": "tcp"},
            }

        else:
            return None

    except Exception:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [ob, {"protocol": "freedom", "tag": "direct"}],
    }


# ── Построение hysteria2-конфига ──────────────────────────────────────────────

def make_hy2_config(uri: str, socks_port: int) -> dict | None:
    try:
        p      = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        cfg: dict = {
            "server": f"{p.hostname}:{p.port or 443}",
            "auth":   p.username or p.password or "",
            "tls": {
                "sni":      params.get("sni", p.hostname or ""),
                "insecure": params.get("insecure", "0") == "1",
            },
            "socks5": {"listen": f"127.0.0.1:{socks_port}"},
        }
        if params.get("obfs") == "salamander":
            cfg["obfs"] = {
                "type": "salamander",
                "salamander": {"password": params.get("obfs-password", "")},
            }
        return cfg
    except Exception:
        return None


# ── Запуск процесса и проверка ────────────────────────────────────────────────

async def _run_and_probe(
    cmd: list[str],
    cfg_path: str,
    socks_port: int,
    startup_delay: float,
) -> tuple[float | None, int]:
    """
    Запускает процесс, ждёт startup_delay, делает curl_probe_all.
    Возвращает (avg_http_ms, probe_ok_count).
    Гарантированно завершает процесс в finally.
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(startup_delay)
        timeout = TIMEOUT_CURL * len(PROBE_URLS) + 8
        http_ms, probe_ok = await asyncio.wait_for(
            curl_probe_all(socks_port), timeout=timeout
        )
        return http_ms, probe_ok
    except Exception:
        return None, 0
    finally:
        if proc:
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except Exception:
            pass


async def stage2_worker(sem: asyncio.Semaphore, idx: int, item: dict) -> dict | None:
    proto      = item["proto"]
    socks_port = SOCKS_BASE_PORT + idx
    uri        = item["uri"]

    async with sem:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            if proto == "hysteria2":
                cfg = make_hy2_config(uri, socks_port)
                if cfg is None:
                    return None
                json.dump(cfg, f)
                cmd = [str(HY2_BIN), "client", "--config", f.name]
                delay = TIMEOUT_HY2_START
            else:
                cfg = make_xray_config(uri, socks_port)
                if cfg is None:
                    return None
                json.dump(cfg, f)
                cmd = [str(XRAY_BIN), "run", "-c", f.name]
                delay = TIMEOUT_XRAY_START
            cfg_path = f.name

        http_ms, probe_ok = await _run_and_probe(cmd, cfg_path, socks_port, delay)
        if http_ms is None:
            return None

        result = {**item, "http_ms": http_ms, "probe_ok": probe_ok}
        result["score"] = compute_score(result)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n{'═'*64}")
    print(f"  Proxy Checker (RU edition) | {ts}")
    print(f"  Протоколы : {ALLOWED_PROTOCOLS}")
    print(f"  Reality   : {REQUIRE_REALITY}")
    print(f"  Страны    : {sorted(ALLOWED_COUNTRIES) or 'все'}")
    print(f"  Probe-URL : {len(PROBE_URLS)} шт → {[u for u,_ in PROBE_URLS]}")
    print(f"{'═'*64}\n")

    # ── 0. Источники ─────────────────────────────────────────────────────────
    print("📄 Загрузка sources.txt…")
    sources = load_sources()
    if not sources:
        print("⚠️  Нет источников, выход.")
        return
    print()

    # ── 1. Скачиваем конфиги ─────────────────────────────────────────────────
    print("📥 Fetching sources…")
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=20)
    ) as sess:
        batches = await asyncio.gather(*[fetch_source(sess, u) for u in sources])

    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    proto_stat: dict[str, int] = {}
    for c in all_configs:
        k = c.split("://")[0].lower()
        proto_stat[k] = proto_stat.get(k, 0) + 1
    print(f"\n📋 Unique configs: {len(all_configs)}")
    print("   " + " | ".join(f"{k}={v}" for k, v in sorted(proto_stat.items())))

    # ── 2. Фильтр протоколов ─────────────────────────────────────────────────
    filtered = filter_configs(all_configs)
    before_dedup = len(filtered)
    filtered = dedup_configs(filtered)
    print(f"\n🔎 После фильтра: {before_dedup} → после дедупликации: {len(filtered)}")
    if not filtered:
        print("⚠️  Ничего не осталось, выход.")
        return

    # ── 3. Stage 1: TCP-ping / DNS-resolve ───────────────────────────────────
    print(f"\n🔌 Stage 1 — TCP-ping  (concurrent={MAX_CONCURRENT_TCP})…")
    sem1 = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    tcp_alive: list[dict] = []
    done = 0
    tasks = [stage1_worker(sem1, u) for u in filtered]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if r:
            tcp_alive.append(r)
        if done % 500 == 0:
            print(f"  … {done}/{len(filtered)} проверено, живых: {len(tcp_alive)}")

    # Hysteria2 (tcp_ms=None) идут после TCP-sorted, но в Stage 2 всё равно попадут
    tcp_alive.sort(key=lambda x: (x["tcp_ms"] is None, x["tcp_ms"] or 0))
    print(f"  ✅ TCP-alive: {len(tcp_alive)}")

    # ── 4. Гео-фильтр ────────────────────────────────────────────────────────
    if ALLOWED_COUNTRIES:
        print("\n🌍 Geo filter…")
        tcp_alive = await geo_filter(tcp_alive)

    if not tcp_alive:
        print("⚠️  После фильтров ничего не осталось.")
        return

    # ── 5. Установка бинарей ─────────────────────────────────────────────────
    print("\n🛠  Binaries…")
    xray_ok = install_xray()
    need_hy2 = any(x["proto"] == "hysteria2" for x in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok   = install_hysteria2() if need_hy2 else False

    # ── 6. Stage 2: curl probe ───────────────────────────────────────────────
    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive: list[dict] = []

    if xray_ok or hy2_ok:
        total_probe = len(PROBE_URLS)
        print(f"\n🌐 Stage 2 — curl probe")
        print(f"   Кандидаты : {len(candidates)}")
        print(f"   Concurrent: {MAX_CONCURRENT_HTTP}")
        print(f"   Probe-URL : {total_probe} × {[u for u,_ in PROBE_URLS]}")
        print(f"   Scoring   : {TCP_W}×tcp + {HTTP_W}×http − {RELIABILITY_BONUS}×(ok−1) − proto_bonus\n")

        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        done2 = 0
        tasks2 = [stage2_worker(sem2, i, it) for i, it in enumerate(candidates)]
        for coro in asyncio.as_completed(tasks2):
            r = await coro
            done2 += 1
            if r:
                http_alive.append(r)
            if done2 % 50 == 0 or done2 == len(candidates):
                print(f"  … {done2}/{len(candidates)} — рабочих: {len(http_alive)}")

        # Сортируем по score (меньше = лучше)
        http_alive.sort(key=lambda x: x["score"])
        top = http_alive[:TOP_N]

        # Статистика
        wp: dict[str, int] = {}
        for r in http_alive:
            wp[r["proto"]] = wp.get(r["proto"], 0) + 1
        fully_reliable = sum(1 for r in http_alive if r.get("probe_ok", 0) >= total_probe)

        print(f"\n  ✅ Stage 2 working : {len(http_alive)}")
        print(f"     По протоколам  : " + " | ".join(f"{k}={v}" for k, v in sorted(wp.items())))
        print(f"     Все {total_probe} probe прошли: {fully_reliable}/{len(http_alive)}")

    else:
        print("  ⚠️  Нет бинарей — сохраняем TCP-alive без Stage 2")
        for r in candidates[:TOP_N]:
            r.setdefault("http_ms", None)
            r.setdefault("probe_ok", 0)
            r["score"] = compute_score(r)
        top = candidates[:TOP_N]
        http_alive = top

    if not top:
        print("⚠️  Рабочих прокси не найдено.")
        return

    # ── 7. Сохранение ────────────────────────────────────────────────────────
    uris = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uris) + "\n", encoding="utf-8")
    b64 = base64.b64encode("\n".join(uris).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    report_data = {
        "updated":        ts,
        "settings": {
            "protocols":       ALLOWED_PROTOCOLS,
            "require_reality": REQUIRE_REALITY,
            "countries":       sorted(ALLOWED_COUNTRIES),
            "probe_urls":      [u for u, _ in PROBE_URLS],
            "top_n":           TOP_N,
        },
        "stats": {
            "sources":      len(sources),
            "total_fetched": len(all_configs),
            "after_filter":  len(filtered),
            "tcp_alive":     len(tcp_alive),
            "http_working":  len(http_alive),
            "saved":         len(top),
        },
        "proxies": [
            {
                "rank":     i + 1,
                "proto":    r["proto"],
                "host":     r["host"],
                "port":     r["port"],
                "tcp_ms":   r.get("tcp_ms"),
                "http_ms":  r.get("http_ms"),
                "probe_ok": r.get("probe_ok", 0),
                "score":    r.get("score"),
                "uri":      r["uri"],
            }
            for i, r in enumerate(top)
        ],
    }
    (OUTPUT_DIR / "report.json").write_text(
        json.dumps(report_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # README
    n_probe = len(PROBE_URLS)
    rows = "\n".join(
        "| {rank} | `{proto}` | `{host}:{port}` | {tcp} | {http} | {rel} | {score} |".format(
            rank  = i + 1,
            proto = r["proto"],
            host  = r["host"],
            port  = r["port"],
            tcp   = f"{r['tcp_ms']} ms" if r.get("tcp_ms") else "UDP",
            http  = f"{r['http_ms']} ms" if r.get("http_ms") else "—",
            rel   = f"{r.get('probe_ok', 0)}/{n_probe}",
            score = int(r.get("score", 0)),
        )
        for i, r in enumerate(top[:50])
    )
    s = report_data["stats"]
    readme = f"""# Proxy Check Results — RU edition

**Updated:** {ts}

| | |
|---|---|
| Источников | {s['sources']} |
| Всего конфигов | {s['total_fetched']} |
| После фильтра | {s['after_filter']} |
| TCP-alive | {s['tcp_alive']} |
| Stage 2 рабочих | {s['http_working']} |
| Сохранено | {s['saved']} |

**Probe-URL:** {", ".join(f"`{u}`" for u, _ in PROBE_URLS)}

**Score** = `{TCP_W}×tcp_ms + {HTTP_W}×http_ms − {RELIABILITY_BONUS}×(probe_ok−1) − proto_bonus` — меньше лучше

## Top 50

| # | Proto | Host:Port | TCP | HTTP | Reliability | Score |
|---|-------|-----------|-----|------|-------------|-------|
{rows}

## Файлы

| Файл | Описание |
|------|----------|
| [`proxies.txt`](proxies.txt) | URI, один на строку |
| [`proxies_b64.txt`](proxies_b64.txt) | Base64-подписка (v2rayNG, Karing, Hiddify) |
| [`report.json`](report.json) | Полный JSON со score и метриками |

---
*Автообновление каждые 3 часа · GitHub Actions*
"""
    (OUTPUT_DIR / "README.md").write_text(readme, encoding="utf-8")
    (REPO_ROOT / "README.md").write_text(
        readme.replace("](proxies", "](output/proxies")
              .replace("](report",  "](output/report"),
        encoding="utf-8",
    )

    # Итог в консоль
    print(f"\n{'─'*64}")
    print(f"📁 Сохранено в {OUTPUT_DIR}/")
    print(f"   proxies.txt     — {len(top)} URI")
    print(f"   proxies_b64.txt — base64 подписка")
    print(f"   report.json     — с score, probe_ok, метриками")
    print(f"\n🏆 Топ 5 (по score):")
    for i, r in enumerate(top[:5]):
        print(
            f"   {i+1}. [{r['proto']}] {r['host']}:{r['port']}"
            f"  tcp={r.get('tcp_ms') or 'UDP'} ms"
            f"  http={r.get('http_ms')} ms"
            f"  rel={r.get('probe_ok', 0)}/{len(PROBE_URLS)}"
            f"  score={int(r.get('score', 0))}"
        )
    print()


if __name__ == "__main__":
    asyncio.run(main())
