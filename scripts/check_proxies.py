#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
Поддерживаемые протоколы: vless, vmess, trojan, ss, hysteria2
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
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Пути ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
REPO_ROOT    = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.yml"
OUTPUT_DIR   = REPO_ROOT / "output"

# ── Тестируем заблокированные в РФ ресурсы ───────────────────────────────────
PROBE_URLS = [
    ("https://api.telegram.org/",               [200, 404]),   # 404 — норма без токена
    ("https://telegram.org/",                   [200, 301, 302]),
    ("https://cp.cloudflare.com/",              [200, 204]),
    ("https://www.google.com/generate_204",     [200, 204]),
]

# ── Настройки ─────────────────────────────────────────────────────────────────
ALLOWED_PROTOCOLS   = ["vless", "hysteria2", "trojan", "ss"]   # добавь "vmess","trojan","ss" при необходимости
REQUIRE_REALITY     = True                     # False — брать любой vless
ALLOWED_COUNTRIES   = set()                    # пусто = без геофильтра; пример: {"NL","DE","EE","RU","FI"}
GEO_BATCH_SIZE      = 100

TOP_N               = 150
TIMEOUT_TCP         = 3
TIMEOUT_CURL        = 10
TIMEOUT_XRAY_START  = 1.0
MAX_CONCURRENT_TCP  = 200
MAX_CONCURRENT_HTTP = 20
STAGE2_CANDIDATES   = 600
SOCKS_BASE_PORT     = 20000

# UDP-порт для Hysteria2 TCP-ping (Hysteria2 слушает на UDP, поэтому stage2 обязателен)
HYSTERIA2_PROBE_TIMEOUT = 12

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN  = Path("/tmp/hysteria-bin/hysteria")


# ═══════════════════════════════════════════════════════════════════════════════
# Загрузка источников из sources.yml
# ═══════════════════════════════════════════════════════════════════════════════

def load_sources() -> list[str]:
    """Читает sources.yml и возвращает плоский список включённых URL."""
    if not SOURCES_FILE.exists():
        print(f"  ⚠️  {SOURCES_FILE} не найден, используем встроенный список")
        return _builtin_sources()

    if not HAS_YAML:
        print("  ⚠️  PyYAML не установлен (pip install pyyaml) — парсим sources.yml вручную")
        return _parse_sources_simple()

    with open(SOURCES_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    urls = []
    for section_name, entries in data.items():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "").strip()
            if url and item.get("enabled", True):
                urls.append(url)

    print(f"  📄 Загружено {len(urls)} источников из {SOURCES_FILE.name}")
    return urls


def _parse_sources_simple() -> list[str]:
    """Резервный парсер без PyYAML — ищет строки '  url: \"...\"'."""
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            m = re.match(r'\s+url:\s+"([^"]+)"', line)
            if m:
                urls.append(m.group(1))
    return urls


def _builtin_sources() -> list[str]:
    return [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
        "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def decode_b64(data: str) -> str:
    data = data.strip()
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return data


def extract_configs(text: str) -> list:
    stripped = text.strip()
    if re.match(r'^[A-Za-z0-9+/\n\r=]{60,}$', stripped):
        decoded = decode_b64(stripped)
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")):
            text = decoded
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")):
            configs.append(line)
    return configs


def filter_configs(configs: list) -> list:
    result = []
    for uri in configs:
        scheme = uri.split("://")[0].lower()
        if ALLOWED_PROTOCOLS and scheme not in ALLOWED_PROTOCOLS:
            continue
        if REQUIRE_REALITY and scheme == "vless":
            if "reality" not in uri.lower():
                continue
        result.append(uri)
    return result


def parse_host_port(uri: str):
    """Возвращает (host, port) или None. Для hysteria2 берём UDP-порт."""
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        if scheme == "hysteria2":
            host = p.hostname
            port = p.port or 443
            if host and port:
                return host, port, "udp"
        else:
            if p.hostname and p.port:
                return p.hostname, p.port, "tcp"
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Hysteria2 helpers
# ═══════════════════════════════════════════════════════════════════════════════

def parse_hysteria2(uri: str) -> dict | None:
    """Парсит hysteria2://password@host:port?param=value#name"""
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        return {
            "host":      p.hostname or "",
            "port":      p.port or 443,
            "auth":      p.username or p.password or "",
            "sni":       params.get("sni", p.hostname or ""),
            "insecure":  params.get("insecure", "0") == "1",
            "obfs":      params.get("obfs", ""),
            "obfs_password": params.get("obfs-password", ""),
            "name":      urllib.parse.unquote(p.fragment or ""),
        }
    except Exception:
        return None


def install_hysteria2() -> bool:
    """Скачивает hysteria2 бинарник с GitHub Releases."""
    if HY2_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи hysteria.exe в {HY2_BIN}")
        return False
    print("  📦 Downloading hysteria2…")
    arch = platform.machine().lower()
    if arch in ("aarch64", "arm64"):
        fname = "hysteria-linux-arm64"
    else:
        fname = "hysteria-linux-amd64"
    url = f"https://github.com/apernet/hysteria/releases/latest/download/{fname}"
    try:
        HY2_BIN.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, HY2_BIN)
        HY2_BIN.chmod(0o755)
        print("  ✓ hysteria2 ready")
        return True
    except Exception as e:
        print(f"  ✗ hysteria2 install failed: {e}")
        return False


async def hy2_probe(item: dict) -> dict | None:
    """Проверяет hysteria2-сервер через клиент hysteria2 + curl."""
    uri  = item["uri"]
    cfg  = parse_hysteria2(uri)
    if not cfg:
        return None

    socks_port = item.get("_socks_port", 20100 + hash(uri) % 10000)

    hy2_config = {
        "server": f"{cfg['host']}:{cfg['port']}",
        "auth":   cfg["auth"],
        "tls": {
            "sni":      cfg["sni"],
            "insecure": cfg["insecure"],
        },
        "socks5": {
            "listen": f"127.0.0.1:{socks_port}",
        },
    }
    if cfg["obfs"] == "salamander":
        hy2_config["obfs"] = {
            "type":       "salamander",
            "salamander": {"password": cfg["obfs_password"]},
        }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(hy2_config, f)
        cfg_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            str(HY2_BIN), "client", "--config", cfg_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(1.5)     # hysteria2 поднимается чуть дольше xray

        t0 = time.monotonic()
        http_lat = await asyncio.wait_for(
            _curl_through_socks(socks_port),
            timeout=HYSTERIA2_PROBE_TIMEOUT,
        )
        if http_lat is None:
            return None
        return {**item, "http_ms": http_lat, "proto": "hysteria2"}
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None
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


async def _curl_through_socks(socks_port: int) -> float | None:
    """Общий вспомогательный метод для curl через SOCKS5."""
    for url, ok_codes in PROBE_URLS:
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
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=TIMEOUT_CURL + 3
            )
            code = int(stdout.decode().strip() or "0")
            if code in ok_codes:
                return round((time.monotonic() - t0) * 1000, 1)
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Geo filter
# ═══════════════════════════════════════════════════════════════════════════════

async def geo_filter(items: list) -> list:
    if not ALLOWED_COUNTRIES:
        return items

    host_map: dict[str, list] = {}
    for item in items:
        host_map.setdefault(item["host"], []).append(item)

    hosts = list(host_map.keys())
    print(f"  🌍 Geo lookup для {len(hosts)} хостов…")

    allowed_hosts: set[str] = set()
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(hosts), GEO_BATCH_SIZE):
            batch = hosts[i:i + GEO_BATCH_SIZE]
            payload = [{"query": h, "fields": "query,countryCode,status"} for h in batch]
            try:
                async with session.post(
                    "http://ip-api.com/batch",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            if entry.get("status") == "success":
                                cc = entry.get("countryCode", "")
                                if cc in ALLOWED_COUNTRIES:
                                    allowed_hosts.add(entry.get("query", ""))
            except Exception as e:
                print(f"  ⚠️  geo error: {e} — пропускаем фильтр для партии")
                allowed_hosts.update(batch)
            await asyncio.sleep(0.5)

    result = [item for item in items if item["host"] in allowed_hosts]
    print(f"  ✅ После геофильтра: {len(result)} / {len(items)}")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 – TCP ping  (hysteria2 идёт по отдельному пути — UDP)
# ═══════════════════════════════════════════════════════════════════════════════

async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT_TCP):
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        lat = (time.monotonic() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return lat
    except Exception:
        return None


async def stage1_test(sem, uri):
    hp = parse_host_port(uri)
    if not hp:
        return None
    host, port, proto_type = hp
    async with sem:
        if proto_type == "udp":
            # Hysteria2 — TCP-пинг не подходит, помечаем как "pre-stage2"
            # Можно сделать UDP-пинг, но это ненадёжно без handshake;
            # поэтому просто проверяем резолвинг хоста
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.getaddrinfo(host, port), timeout=TIMEOUT_TCP
                )
                return {"uri": uri, "host": host, "port": port, "tcp_ms": 0,
                        "proto": "hysteria2"}
            except Exception:
                return None
        else:
            lat = await tcp_ping(host, port)
            if lat is None:
                return None
            return {"uri": uri, "host": host, "port": port, "tcp_ms": round(lat, 1),
                    "proto": uri.split("://")[0].lower()}


# ═══════════════════════════════════════════════════════════════════════════════
# Xray install
# ═══════════════════════════════════════════════════════════════════════════════

def install_xray() -> bool:
    if XRAY_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи xray.exe в {XRAY_BIN}")
        return False
    print("  📦 Downloading xray-core…")
    arch = platform.machine().lower()
    fname = "Xray-linux-arm64-v8a.zip" if arch in ("aarch64", "arm64") else "Xray-linux-64.zip"
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{fname}"
    tmpzip = Path("/tmp/xray.zip")
    try:
        urllib.request.urlretrieve(url, tmpzip)
        XRAY_BIN.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmpzip, "r") as z:
            z.extractall(XRAY_BIN.parent)
        XRAY_BIN.chmod(0o755)
        print("  ✓ xray-core ready")
        return True
    except Exception as e:
        print(f"  ✗ xray install failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2 – xray config builders  (vless / vmess / trojan / ss)
# ═══════════════════════════════════════════════════════════════════════════════

def make_xray_config(uri: str, socks_port: int) -> dict | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vless":
            p      = urllib.parse.urlparse(uri)
            uid    = p.username or ""
            host   = p.hostname or ""
            port   = p.port or 443
            params = dict(urllib.parse.parse_qsl(p.query))
            flow   = params.get("flow", "")
            sni    = params.get("sni", params.get("peer", host))
            fp     = params.get("fp", "chrome")
            net    = params.get("type", "tcp")
            sec    = params.get("security", "none")
            pbk    = params.get("pbk", "")
            sid    = params.get("sid", "")
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port,
                    "users": [{"id": uid, "encryption": "none", "flow": flow}]}]},
                "streamSettings": {"network": net},
            }
            ss = outbound["streamSettings"]
            if sec == "reality":
                ss["security"] = "reality"
                ss["realitySettings"] = {
                    "serverName": sni, "fingerprint": fp,
                    "publicKey": pbk, "shortId": sid,
                }
            elif sec == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "allowInsecure": True}
            if net == "ws":
                ss["wsSettings"] = {"path": params.get("path", "/"),
                                     "headers": {"Host": params.get("host", host)}}
            elif net == "grpc":
                ss["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

        elif scheme == "trojan":
            p      = urllib.parse.urlparse(uri)
            host   = p.hostname or ""
            port   = p.port or 443
            params = dict(urllib.parse.parse_qsl(p.query))
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port,
                                           "password": p.username or ""}]},
                "streamSettings": {"network": "tcp", "security": "tls",
                                   "tlsSettings": {"serverName": params.get("sni", host),
                                                   "allowInsecure": True}},
            }

        elif scheme == "vmess":
            raw  = decode_b64(uri[len("vmess://"):])
            cfg  = json.loads(raw)
            host = cfg.get("add", "")
            port = int(cfg.get("port", 443))
            net  = cfg.get("net", "tcp")
            tls  = cfg.get("tls", "")
            sni  = cfg.get("sni", cfg.get("host", host))
            outbound = {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": host, "port": port,
                    "users": [{"id": cfg.get("id", ""), "alterId": int(cfg.get("aid", 0)),
                               "security": "auto"}]}]},
                "streamSettings": {"network": net},
            }
            ss = outbound["streamSettings"]
            if tls == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
            if net == "ws":
                ss["wsSettings"] = {"path": cfg.get("path", "/"),
                                     "headers": {"Host": cfg.get("host", host)}}

        elif scheme == "ss":
            p        = urllib.parse.urlparse(uri)
            userinfo = p.username or ""
            if ":" not in userinfo:
                userinfo = decode_b64(userinfo)
            method, password = userinfo.split(":", 1)
            outbound = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": p.hostname or "", "port": p.port or 443,
                                           "method": method, "password": password}]},
                "streamSettings": {"network": "tcp"},
            }
        else:
            return None

    except Exception:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


async def curl_probe(socks_port: int) -> float | None:
    return await _curl_through_socks(socks_port)


async def stage2_test(sem, idx: int, item: dict) -> dict | None:
    uri    = item["uri"]
    scheme = uri.split("://")[0].lower()

    # Hysteria2 обрабатываем отдельно
    if scheme == "hysteria2":
        item["_socks_port"] = SOCKS_BASE_PORT + 10000 + idx
        async with sem:
            return await hy2_probe(item)

    socks_port = SOCKS_BASE_PORT + idx
    cfg = make_xray_config(uri, socks_port)
    if cfg is None:
        return None

    async with sem:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            cfg_path = f.name
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                str(XRAY_BIN), "run", "-c", cfg_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(TIMEOUT_XRAY_START)
            try:
                http_lat = await asyncio.wait_for(
                    curl_probe(socks_port),
                    timeout=TIMEOUT_CURL + 5,
                )
            except asyncio.TimeoutError:
                return None
            if http_lat is None:
                return None
            return {**item, "http_ms": http_lat}
        except Exception:
            return None
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


# ═══════════════════════════════════════════════════════════════════════════════
# Fetch sources
# ═══════════════════════════════════════════════════════════════════════════════

async def fetch_source(session, url: str) -> list:
    url = re.sub(r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
                 r'raw.githubusercontent.com/\1/\2/refs/heads/\3', url)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as resp:
            if resp.status == 200:
                text = await resp.text(encoding="utf-8", errors="ignore")
                configs = extract_configs(text)
                print(f"  ✓ {url[:72]}  →  {len(configs)} configs")
                return configs
            print(f"  ✗ {url[:72]}  →  HTTP {resp.status}")
    except Exception as e:
        print(f"  ✗ {url[:72]}  →  {e}")
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{'='*64}")
    print(f"  Proxy Checker (RU edition)  |  {ts}")
    print(f"  Протоколы: {ALLOWED_PROTOCOLS}")
    print(f"  Страны: {sorted(ALLOWED_COUNTRIES) or 'все'}")
    print(f"{'='*64}\n")

    # 0. Загрузка источников
    print("📄 Loading sources…")
    SOURCES = load_sources()
    print()

    # 1. Download
    print("📥 Fetching sources…")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as s:
        batches = await asyncio.gather(*[fetch_source(s, u) for u in SOURCES])
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Unique configs: {len(all_configs)}")

    # Статистика по протоколам
    proto_counts: dict[str, int] = {}
    for c in all_configs:
        proto = c.split("://")[0].lower()
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    print("  Протоколы: " + ", ".join(f"{k}={v}" for k, v in sorted(proto_counts.items())))

    # 2. Filter by protocol
    filtered = filter_configs(all_configs)
    print(f"🔎 After protocol filter: {len(filtered)}\n")
    if not filtered:
        print("⚠️  No configs after filtering.")
        return

    # 3. Stage 1 – TCP ping / DNS resolve
    print(f"🔌 Stage 1 – TCP ping  (concurrency={MAX_CONCURRENT_TCP})…")
    sem1 = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    tcp_alive, done = [], 0
    for coro in asyncio.as_completed([stage1_test(sem1, u) for u in filtered]):
        r = await coro
        done += 1
        if r:
            tcp_alive.append(r)
        if done % 300 == 0:
            print(f"  … {done}/{len(filtered)} pinged, {len(tcp_alive)} alive")
    # Hysteria2 в Stage1 имеет tcp_ms=0, поэтому сортируем с учётом этого
    tcp_alive.sort(key=lambda x: (x["tcp_ms"] == 0, x["tcp_ms"]))
    print(f"  ✅ TCP-alive: {len(tcp_alive)}\n")

    # 4. Geo filter
    print("🌍 Geo filter…")
    tcp_alive = await geo_filter(tcp_alive)
    print()

    if not tcp_alive:
        print("⚠️  После геофильтра не осталось прокси.")
        return

    # 5. Install binaries
    print("🛠  Preparing binaries…")
    xray_ok = install_xray()
    # Hysteria2 нужен только если есть конфиги
    hy2_configs_exist = any(i["uri"].startswith("hysteria2://") for i in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok = install_hysteria2() if hy2_configs_exist else False

    # 6. Stage 2 – curl через xray/hysteria2 SOCKS5
    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive = []

    if xray_ok or hy2_ok:
        print(f"\n🌐 Stage 2 – curl probe  ({len(candidates)} candidates, concurrency={MAX_CONCURRENT_HTTP})")
        print(f"   URLs: {' | '.join(u for u, _ in PROBE_URLS)}\n")
        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        done2 = 0
        for coro in asyncio.as_completed([stage2_test(sem2, i, it) for i, it in enumerate(candidates)]):
            r = await coro
            done2 += 1
            if r:
                http_alive.append(r)
            if done2 % 50 == 0 or done2 == len(candidates):
                print(f"  … {done2}/{len(candidates)} tested, {len(http_alive)} working")
        http_alive.sort(key=lambda x: x["http_ms"])
        top = http_alive[:TOP_N]
        print(f"\n  ✅ HTTP-working: {len(http_alive)}")

        # Статистика по протоколам среди рабочих
        working_protos: dict[str, int] = {}
        for r in http_alive:
            p = r.get("proto", r["uri"].split("://")[0].lower())
            working_protos[p] = working_protos.get(p, 0) + 1
        if working_protos:
            print("  По протоколам: " + ", ".join(f"{k}={v}" for k, v in sorted(working_protos.items())))
    else:
        print("  ⚠️  Нет доступных бинарников — сохраняем TCP-alive")
        top = candidates[:TOP_N]
        for r in top:
            r["http_ms"] = None

    if not top:
        print("⚠️  No working proxies found.")
        return

    # 7. Save
    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    report = {
        "updated":       ts,
        "countries":     sorted(ALLOWED_COUNTRIES),
        "protocols":     ALLOWED_PROTOCOLS,
        "total_fetched": len(all_configs),
        "after_filter":  len(filtered),
        "tcp_alive":     len(tcp_alive),
        "http_working":  len(http_alive) if (xray_ok or hy2_ok) else "n/a",
        "saved":         len(top),
        "probe_urls":    [u for u, _ in PROBE_URLS],
        "proxies":       top,
    }
    (OUTPUT_DIR / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rows = "\n".join(
        "| {n} | `{proto}` | `{h}:{p}` | {tcp} | {http} |".format(
            n=i+1,
            proto=r.get("proto", r["uri"].split("://")[0].lower()),
            h=r["host"], p=r["port"],
            tcp=f"{r['tcp_ms']} ms" if r["tcp_ms"] else "UDP",
            http=f"{r['http_ms']} ms" if r.get("http_ms") else "—",
        )
        for i, r in enumerate(top[:50])
    )
    readme_output = f"""# Proxy Check Results (RU edition)

**Updated:** {ts}

| Stat | Value |
|------|-------|
| Sources | {len(SOURCES)} |
| Total configs | {len(all_configs)} |
| After filter | {len(filtered)} |
| TCP alive | {len(tcp_alive)} |
| HTTP working | {len(http_alive) if (xray_ok or hy2_ok) else "n/a"} |
| Saved top | {len(top)} |

Страны: {", ".join(sorted(ALLOWED_COUNTRIES)) or "все"}
Протоколы: {", ".join(ALLOWED_PROTOCOLS)}

## Top 50 by HTTP latency

| # | Proto | Host:Port | TCP | HTTP |
|---|-------|-----------|-----|------|
{rows}

## Files

| File | Description |
|------|-------------|
| [`proxies.txt`](proxies.txt) | Plain URI — один на строку |
| [`proxies_b64.txt`](proxies_b64.txt) | Base64 подписка для Karing / v2rayNG |
| [`report.json`](report.json) | Полный JSON с латентностями |

---
*Обновляется каждые 3 часа · GitHub Actions*
"""
    (OUTPUT_DIR / "README.md").write_text(readme_output, encoding="utf-8")
    Path(REPO_ROOT / "README.md").write_text(
        readme_output.replace("](proxies", "](output/proxies").replace("](report", "](output/report"),
        encoding="utf-8",
    )

    print(f"\n📁 Сохранено в {OUTPUT_DIR}/")
    print(f"   proxies.txt      — {len(top)} URI")
    print(f"   proxies_b64.txt  — base64 подписка\n")
    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        proto = r.get("proto", r["uri"].split("://")[0].lower())
        http  = f"{r['http_ms']} ms" if r.get("http_ms") else f"TCP {r['tcp_ms']} ms"
        print(f"   {i+1}. [{proto}] {r['host']}:{r['port']}  →  {http}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
