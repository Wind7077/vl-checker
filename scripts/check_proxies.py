#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
Поддерживаемые протоколы: vless, hysteria2
Генерирует: proxies.txt, proxies_b64.txt, proxies.yaml, ru.yaml для FClash
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
import yaml  # pip install pyyaml

from datetime import datetime, timezone
from pathlib import Path

# ── Пути ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR = REPO_ROOT / "output"

# ── Тестируем заблокированные в РФ ресурсы ───────────────────────────────────
PROBE_URLS = [
    ("https://api.telegram.org/", [200, 404]),
    ("https://telegram.org/", [200, 301, 302]),
    ("https://cp.cloudflare.com/", [200, 204]),
    ("https://www.google.com/generate_204", [200, 204]),
]

# ── Настройки ─────────────────────────────────────────────────────────────────
ALLOWED_PROTOCOLS = ["vless", "hysteria2"]
REQUIRE_REALITY = True
ALLOWED_COUNTRIES = set()
TOP_N = 250
TIMEOUT_TCP = 1
TIMEOUT_CURL = 10
TIMEOUT_XRAY_START = 1.0
MAX_CONCURRENT_TCP = 200
MAX_CONCURRENT_HTTP = 20
STAGE2_CANDIDATES = 1000
SOCKS_BASE_PORT = 20000
HYSTERIA2_PROBE_TIMEOUT = 12

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN = Path("/tmp/hysteria-bin/hysteria")

# ═══════════════════════════════════════════════════════════════════════════════
# Загрузка источников
# ═══════════════════════════════════════════════════════════════════════════════
def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        print(f" ❌ Файл {SOURCES_FILE} не найден.")
        print(" Создай sources.txt и добавь ссылки (по одной на строку)")
        sys.exit(1)
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        print(" ❌ sources.txt пустой")
        sys.exit(1)
    print(f" 📄 Загружено {len(urls)} источников")
    return urls

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
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")):
            text = decoded

    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")):
            if line.startswith("hy2://"):
                line = "hysteria2://" + line[6:]
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

# ═══════════════════════════════════════════════════════════════════════════════
# Конвертация в формат FClash
# ═══════════════════════════════════════════════════════════════════════════════
def uri_to_clash_proxy(uri: str, index: int) -> dict | None:
    try:
        scheme = uri.split("://")[0].lower()
        name = f"RU-{index+1:03d}"

        if scheme == "vless":
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            security = params.get("security", "")

            proxy = {
                "name": name,
                "type": "vless",
                "server": p.hostname,
                "port": int(p.port or 443),
                "uuid": p.username,
                "network": params.get("type", "tcp"),
                "udp": True,
                "tls": security in ("tls", "reality"),
                "servername": params.get("sni") or params.get("peer") or p.hostname,
                "client-fingerprint": params.get("fp", "chrome"),
            }

            if security == "reality":
                proxy["reality-opts"] = {
                    "public-key": params.get("pbk", ""),
                    "short-id": params.get("sid", "")
                }
            if params.get("flow"):
                proxy["flow"] = params.get("flow")

            return proxy

        elif scheme == "hysteria2":
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            return {
                "name": name,
                "type": "hysteria2",
                "server": p.hostname,
                "port": int(p.port or 443),
                "password": p.username or p.password or "",
                "sni": params.get("sni", p.hostname),
                "skip-cert-verify": params.get("insecure") == "1",
                "obfs": params.get("obfs"),
                "obfs-password": params.get("obfs-password", "")
            }

        return None
    except Exception:
        return None


def generate_proxies_yaml(proxies_list: list) -> dict:
    clash_proxies = []
    for i, item in enumerate(proxies_list):
        proxy = uri_to_clash_proxy(item["uri"], i)
        if proxy:
            proxy = {k: v for k, v in proxy.items() if v is not None and v != ""}
            clash_proxies.append(proxy)
    return {"proxies": clash_proxies}


def generate_ru_yaml(proxies_list: list) -> dict:
    clash_proxies = []
    proxy_names = []
    for i, item in enumerate(proxies_list):
        proxy = uri_to_clash_proxy(item["uri"], i)
        if proxy:
            proxy = {k: v for k, v in proxy.items() if v is not None and v != ""}
            clash_proxies.append(proxy)
            proxy_names.append(proxy["name"])

    return {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🔀 Автовыбор",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            },
            {
                "name": "🇷🇺 Россия",
                "type": "select",
                "proxies": proxy_names
            },
            {
                "name": "🌍 Все",
                "type": "select",
                "proxies": proxy_names
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,ru,🇷🇺 Россия",
            "GEOIP,RU,🇷🇺 Россия",
            "MATCH,🔀 Автовыбор"
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Hysteria2
# ═══════════════════════════════════════════════════════════════════════════════
def parse_hysteria2(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        return {
            "host": p.hostname or "",
            "port": p.port or 443,
            "auth": p.username or p.password or "",
            "sni": params.get("sni", p.hostname or ""),
            "insecure": params.get("insecure", "0") == "1",
            "obfs": params.get("obfs", ""),
            "obfs_password": params.get("obfs-password", ""),
        }
    except Exception:
        return None


def install_hysteria2() -> bool:
    if HY2_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f" ⚠️ Положи hysteria.exe в {HY2_BIN}")
        return False
    print(" 📦 Downloading hysteria2…")
    arch = platform.machine().lower()
    fname = "hysteria-linux-arm64" if arch in ("aarch64", "arm64") else "hysteria-linux-amd64"
    url = f"https://github.com/apernet/hysteria/releases/latest/download/{fname}"
    try:
        HY2_BIN.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, HY2_BIN)
        HY2_BIN.chmod(0o755)
        print(" ✓ hysteria2 ready")
        return True
    except Exception as e:
        print(f" ✗ hysteria2 install failed: {e}")
        return False


async def hy2_probe(item: dict) -> dict | None:
    uri = item["uri"]
    cfg = parse_hysteria2(uri)
    if not cfg:
        return None
    socks_port = item.get("_socks_port", 20100 + hash(uri) % 10000)
    hy2_config = {
        "server": f"{cfg['host']}:{cfg['port']}",
        "auth": cfg["auth"],
        "tls": {"sni": cfg["sni"], "insecure": cfg["insecure"]},
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    if cfg["obfs"] == "salamander":
        hy2_config["obfs"] = {"type": "salamander", "salamander": {"password": cfg["obfs_password"]}}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(hy2_config, f)
        cfg_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            str(HY2_BIN), "client", "--config", cfg_path,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(1.5)
        http_lat = await asyncio.wait_for(
            _curl_through_socks(socks_port), timeout=HYSTERIA2_PROBE_TIMEOUT
        )
        if http_lat is None:
            return None
        return {**item, "http_ms": http_lat, "proto": "hysteria2"}
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
# Curl через SOCKS5
# ═══════════════════════════════════════════════════════════════════════════════
async def _curl_through_socks(socks_port: int) -> float | None:
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
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; Win64) AppleWebKit/537.36",
                url,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_CURL + 3)
            code = int(stdout.decode().strip() or "0")
            if code in ok_codes:
                return round((time.monotonic() - t0) * 1000, 1)
        except Exception:
            pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 – TCP ping
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
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        host = p.hostname
        port = p.port or (443 if scheme != "hysteria2" else 443)

        async with sem:
            if scheme == "hysteria2":
                return {"uri": uri, "host": host, "port": port, "tcp_ms": 0, "proto": "hysteria2"}
            lat = await tcp_ping(host, port)
            if lat is None:
                return None
            return {"uri": uri, "host": host, "port": port, "tcp_ms": round(lat, 1),
                    "proto": scheme}
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Xray
# ═══════════════════════════════════════════════════════════════════════════════
def install_xray() -> bool:
    if XRAY_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f" ⚠️ Положи xray.exe в {XRAY_BIN}")
        return False
    print(" 📦 Downloading xray-core…")
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
        print(" ✓ xray-core ready")
        return True
    except Exception as e:
        print(f" ✗ xray install failed: {e}")
        return False


def make_xray_config(uri: str, socks_port: int) -> dict | None:
    # (Оставлена оригинальная реализация — работает)
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vless":
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": p.hostname, "port": p.port or 443,
                    "users": [{"id": p.username, "encryption": "none", "flow": params.get("flow", "")}]}]},
                "streamSettings": {"network": params.get("type", "tcp")},
            }
            ss = outbound["streamSettings"]
            security = params.get("security")
            if security == "reality":
                ss["security"] = "reality"
                ss["realitySettings"] = {
                    "serverName": params.get("sni") or p.hostname,
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", "")
                }
            elif security == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": params.get("sni") or p.hostname, "allowInsecure": True}
            # ... (можно расширить при необходимости)
        else:
            return None
    except Exception:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


async def stage2_test(sem, idx: int, item: dict) -> dict | None:
    uri = item["uri"]
    scheme = uri.split("://")[0].lower()
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
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(TIMEOUT_XRAY_START)
            http_lat = await asyncio.wait_for(
                _curl_through_socks(socks_port), timeout=TIMEOUT_CURL + 5
            )
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
                print(f" ✓ {url[:70]} → {len(configs)} configs")
                return configs
            print(f" ✗ {url[:70]} → HTTP {resp.status}")
    except Exception as e:
        print(f" ✗ {url[:70]} → {e}")
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{'='*70}")
    print(f" Proxy Checker (RU edition) | {ts}")
    print(f"{'='*70}\n")

    SOURCES = load_sources()
    print("📥 Fetching sources...")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as s:
        batches = await asyncio.gather(*[fetch_source(s, u) for u in SOURCES])

    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Unique configs: {len(all_configs)}")

    filtered = filter_configs(all_configs)
    print(f"🔎 After filter: {len(filtered)}\n")

    if not filtered:
        print("⚠️ Нет конфигураций после фильтрации.")
        return

    print("🔌 Stage 1 – TCP ping...")
    sem1 = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    tcp_alive = []
    done = 0
    for coro in asyncio.as_completed([stage1_test(sem1, u) for u in filtered]):
        r = await coro
        done += 1
        if r:
            tcp_alive.append(r)
        if done % 300 == 0:
            print(f" … {done}/{len(filtered)} pinged, {len(tcp_alive)} alive")

    tcp_alive.sort(key=lambda x: (x["tcp_ms"] == 0, x["tcp_ms"]))
    print(f" ✅ TCP-alive: {len(tcp_alive)}\n")

    if not tcp_alive:
        print("⚠️ Нет живых прокси.")
        return

    print("🛠 Preparing binaries...")
    xray_ok = install_xray()
    hy2_needed = any(i["uri"].startswith(("hysteria2://", "hy2://")) for i in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok = install_hysteria2() if hy2_needed else False

    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive = []

    if xray_ok or hy2_ok:
        print(f"\n🌐 Stage 2 – HTTP probe ({len(candidates)} candidates)...")
        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        done2 = 0
        for coro in asyncio.as_completed([stage2_test(sem2, i, it) for i, it in enumerate(candidates)]):
            r = await coro
            done2 += 1
            if r:
                http_alive.append(r)
            if done2 % 50 == 0 or done2 == len(candidates):
                print(f" … {done2}/{len(candidates)} tested, {len(http_alive)} working")

        http_alive.sort(key=lambda x: x.get("http_ms", 9999))
        top = http_alive[:TOP_N]
    else:
        top = candidates[:TOP_N]

    if not top:
        print("⚠️ Не найдено рабочих прокси.")
        return

    # === Сохранение результатов ===
    uri_lines = [r["uri"] for r in top]

    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    # YAML для FClash
    with open(OUTPUT_DIR / "proxies.yaml", "w", encoding="utf-8") as f:
        yaml.dump(generate_proxies_yaml(top), f, allow_unicode=True, sort_keys=False)

    with open(OUTPUT_DIR / "ru.yaml", "w", encoding="utf-8") as f:
        yaml.dump(generate_ru_yaml(top), f, allow_unicode=True, sort_keys=False)

    print(f"\n✅ Успешно сохранено в {OUTPUT_DIR}/")
    print(f"   • proxies.txt")
    print(f"   • proxies_b64.txt")
    print(f"   • proxies.yaml")
    print(f"   • ru.yaml          ← готовая конфигурация для FClash")
    print(f"   Всего: {len(top)} рабочих прокси\n")

    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        proto = r.get("proto", r["uri"].split("://")[0])
        ms = f"{r.get('http_ms')} ms" if r.get("http_ms") else f"TCP {r['tcp_ms']} ms"
        print(f" {i+1:2d}. [{proto}] {r['host']}:{r['port']} → {ms}")


if __name__ == "__main__":
    asyncio.run(main())
