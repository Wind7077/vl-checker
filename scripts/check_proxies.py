#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (Ростелеком, МТС, Билайн, Мегафон)
─────────────────────────────────────────────────────────────────────────────
Stage 1 : TCP-ping (быстрый фильтр)
Stage 2 : curl через xray SOCKS5 — реальная проверка HTTP
          Тестирует именно заблокированные в РФ ресурсы
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

# ── Sources ───────────────────────────────────────────────────────────────────
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://key.zarazaex.xyz/sub",
    "https://raw.githubusercontent.com/Wind7077/vl-auto/refs/heads/main/vless_normal_vpn.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # дополнительные источники специально для РФ
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/vless.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/trojan.txt",
]

# ── Тестируем именно заблокированные в РФ ресурсы ───────────────────────────
# Если прокси открывает эти сайты — он точно работает для России
PROBE_URLS = [
    ("https://telegram.org/",              [200, 301, 302]),
    ("https://www.youtube.com/generate_204", [200, 204]),
    ("https://www.google.com/generate_204", [200, 204]),
    ("https://cp.cloudflare.com/",          [200, 204]),
    ("https://instagram.com/",              [200, 301, 302]),
]

# ── Настройки ─────────────────────────────────────────────────────────────────
ALLOWED_PROTOCOLS   = []     # [] = все (vless, vmess, trojan, ss)
REQUIRE_REALITY     = False  # False = берём все, не только reality

# Оставляем только прокси из этих стран (коды ISO 3166-1 alpha-2)
# Нидерланды, Германия, Эстония, Россия, Финляндия
ALLOWED_COUNTRIES   = {"NL", "DE", "EE", "RU", "FI"}
GEO_BATCH_SIZE      = 100   # ip-api.com принимает до 100 IP за раз (бесплатно)

TOP_N               = 100
OUTPUT_DIR          = Path("output")
TIMEOUT_TCP         = 5
TIMEOUT_CURL        = 20     # увеличен — некоторые рабочие прокси медленные
TIMEOUT_XRAY_START  = 1.5   # ждём запуска xray
MAX_CONCURRENT_TCP  = 200
MAX_CONCURRENT_HTTP = 35
STAGE2_CANDIDATES   = 800   # берём больше кандидатов на HTTP-тест
SOCKS_BASE_PORT     = 20000

# xray путь — автоматически под Windows и Linux
if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")


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
    # пробуем декодировать base64-подписку
    stripped = text.strip()
    if re.match(r'^[A-Za-z0-9+/\n\r=]{60,}$', stripped):
        decoded = decode_b64(stripped)
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://", "ss://")):
            text = decoded
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
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
# Geo filter — оставляем только NL, DE, EE, RU, FI
# ═══════════════════════════════════════════════════════════════════════════════

async def geo_filter(items: list) -> list:
    """
    Принимает список {"uri":..., "host":..., "port":...}
    Возвращает только те, чей IP находится в ALLOWED_COUNTRIES.
    Использует ip-api.com batch API (бесплатно, до 100 IP за запрос).
    """
    if not ALLOWED_COUNTRIES:
        return items

    # собираем уникальные хосты
    host_map: dict[str, list] = {}   # host -> [items]
    for item in items:
        host_map.setdefault(item["host"], []).append(item)

    hosts = list(host_map.keys())
    print(f"  🌍 Geo lookup для {len(hosts)} уникальных хостов…")

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
                print(f"  ⚠️  geo batch error: {e} — пропускаем фильтр для этой партии")
                # если geo API не ответил — не отбрасываем хосты
                allowed_hosts.update(batch)
            await asyncio.sleep(0.5)   # ip-api rate limit: 15 req/min бесплатно

    result = [item for item in items if item["host"] in allowed_hosts]

    # статистика по странам
    country_count: dict[str, int] = {}
    for item in result:
        cc = item.get("country", "?")
        country_count[cc] = country_count.get(cc, 0) + 1

    print(f"  ✅ После геофильтра: {len(result)} / {len(items)}")
    print(f"     Разрешённые страны: {sorted(ALLOWED_COUNTRIES)}")
    return result


def parse_host_port(uri: str):
    try:
        p = urllib.parse.urlparse(uri)
        if p.hostname and p.port:
            return p.hostname, p.port
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
    hp = parse_host_port(uri)
    if not hp:
        return None
    host, port = hp
    async with sem:
        lat = await tcp_ping(host, port)
        if lat is None:
            return None
        return {"uri": uri, "host": host, "port": port, "tcp_ms": round(lat, 1)}


# ═══════════════════════════════════════════════════════════════════════════════
# Xray install (только для Linux/CI)
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
# Stage 2 – xray config builders
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
    """curl через SOCKS5 — проверяет заблокированные в РФ сайты."""
    for url, ok_codes in PROBE_URLS:
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                "--max-time", str(TIMEOUT_CURL),
                "--connect-timeout", "10",
                "-w", "%{http_code}",
                "--insecure",
                "-L",           # следуем редиректам
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                url,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=TIMEOUT_CURL + 5
            )
            code = int(stdout.decode().strip() or "0")
            if code in ok_codes:
                lat = (time.monotonic() - t0) * 1000
                return round(lat, 1)
        except Exception:
            pass
    return None


async def stage2_test(sem, idx: int, item: dict) -> dict | None:
    uri = item["uri"]
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
            http_lat = await curl_probe(socks_port)
            if http_lat is None:
                return None
            return {**item, "http_ms": http_lat}
        except Exception:
            return None
        finally:
            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except Exception:
                    try: proc.kill()
                    except Exception: pass
            try: os.unlink(cfg_path)
            except Exception: pass


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
    print(f"  Protocols: {ALLOWED_PROTOCOLS or 'all'}  |  Reality only: {REQUIRE_REALITY}")
    print(f"{'='*64}\n")

    # 1. Download
    print("📥 Fetching sources…")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as s:
        batches = await asyncio.gather(*[fetch_source(s, u) for u in SOURCES])
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Unique configs: {len(all_configs)}")

    # 2. Filter
    filtered = filter_configs(all_configs)
    print(f"🔎 After filter: {len(filtered)}\n")
    if not filtered:
        print("⚠️  No configs after filtering.")
        return

    # 3. Stage 1 – TCP ping
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
    tcp_alive.sort(key=lambda x: x["tcp_ms"])
    print(f"  ✅ TCP-alive: {len(tcp_alive)}\n")

    # 4. Geo filter — только NL, DE, EE, RU, FI
    print(f"🌍 Geo filter  (страны: {sorted(ALLOWED_COUNTRIES)})…")
    tcp_alive = await geo_filter(tcp_alive)
    print()

    # 5. Install xray
    print("🛠  Preparing xray-core…")
    xray_ok = install_xray()

    # 6. Stage 2 – curl через xray SOCKS5
    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive = []

    if xray_ok:
        print(f"\n🌐 Stage 2 – curl probe  ({len(candidates)} candidates, concurrency={MAX_CONCURRENT_HTTP})")
        print(f"   Тестируем заблокированные в РФ сайты…\n")
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
    else:
        print("  ⚠️  xray unavailable — saving TCP-alive only (без проверки URL)")
        top = candidates[:TOP_N]
        for r in top:
            r["http_ms"] = None

    if not top:
        print("⚠️  No working proxies found.")
        return

    # 6. Save
    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    report = {
        "updated": ts,
        "filter": {"protocols": ALLOWED_PROTOCOLS or "all", "reality_only": REQUIRE_REALITY},
        "total_fetched": len(all_configs),
        "after_filter": len(filtered),
        "tcp_alive": len(tcp_alive),
        "http_working": len(http_alive) if xray_ok else "n/a",
        "saved": len(top),
        "probe_urls": [u for u, _ in PROBE_URLS],
        "proxies": top,
    }
    (OUTPUT_DIR / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rows = "\n".join(
        "| {n} | `{h}:{p}` | {tcp} ms | {http} |".format(
            n=i+1, h=r["host"], p=r["port"],
            tcp=r["tcp_ms"],
            http=f"{r['http_ms']} ms" if r.get("http_ms") else "—",
        )
        for i, r in enumerate(top[:50])
    )
    probe_str = " · ".join(f"`{u}`" for u, _ in PROBE_URLS)
    readme_output = f"""# Proxy Check Results (RU edition)

**Updated:** {ts}

| Stat | Value |
|------|-------|
| Sources | {len(SOURCES)} |
| Total configs | {len(all_configs)} |
| After filter | {len(filtered)} |
| TCP alive | {len(tcp_alive)} |
| HTTP working | {len(http_alive) if xray_ok else "n/a"} |
| Saved top | {len(top)} |

Probe URLs (заблокированные в РФ): {probe_str}

## Top 50 by HTTP latency

| # | Host:Port | TCP | HTTP |
|---|-----------|-----|------|
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
    Path("README.md").write_text(
        readme_output.replace("](proxies", "](output/proxies").replace("](report", "](output/report"),
        encoding="utf-8",
    )

    print(f"\n📁 Сохранено в {OUTPUT_DIR}/")
    print(f"   proxies.txt      — {len(top)} URI")
    print(f"   proxies_b64.txt  — base64 подписка\n")
    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        http = f"{r['http_ms']} ms" if r.get("http_ms") else f"TCP {r['tcp_ms']} ms"
        print(f"   {i+1}. {r['host']}:{r['port']}  →  {http}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
