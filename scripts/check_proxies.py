#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
Поддерживаемые протоколы: vless, hysteria2
Генерирует: proxies.txt, ru.txt, proxie#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
Поддерживаемые протоколы: vless, vmess, trojan, ss, hysteria2
Источники: sources.txt рядом со скриптом (одна строка = один URL, # = комментарий)
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

# ── Пути ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
REPO_ROOT    = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR   = REPO_ROOT / "output"

# ── Тестируем заблокированные в РФ ресурсы ───────────────────────────────────
PROBE_URLS = [
    ("https://api.telegram.org/",           [200, 404]),
    ("https://telegram.org/",               [200, 301, 302]),
    ("https://cp.cloudflare.com/",          [200, 204]),
    ("https://www.google.com/generate_204", [200, 204]),
]

# ── Настройки ─────────────────────────────────────────────────────────────────
ALLOWED_PROTOCOLS   = ["vless", "hysteria2"]   # добавь "vmess","trojan","ss" при необходимости
REQUIRE_REALITY     = True                     # False — брать любой vless
ALLOWED_COUNTRIES   = set()                    # пусто = без геофильтра; пример: {"NL","DE","EE","RU","FI"}
GEO_BATCH_SIZE      = 100

TOP_N               = 250
TIMEOUT_TCP         = 1
TIMEOUT_CURL        = 10
TIMEOUT_XRAY_START  = 1.0
MAX_CONCURRENT_TCP  = 200
MAX_CONCURRENT_HTTP = 20
STAGE2_CANDIDATES   = 1000
SOCKS_BASE_PORT     = 20000

HYSTERIA2_PROBE_TIMEOUT = 12

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN  = Path("/tmp/hysteria-bin/hysteria")


# ═══════════════════════════════════════════════════════════════════════════════
# Загрузка источников из sources.txt
# ═══════════════════════════════════════════════════════════════════════════════

def load_sources() -> list[str]:
    """Читает sources.txt — одна строка = один URL, строки с # игнорируются."""
    if not SOURCES_FILE.exists():
        print(f"  ❌ Файл {SOURCES_FILE} не найден.")
        print(f"     Создай его и добавь URL источников (по одному на строку).")
        sys.exit(1)

    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    if not urls:
        print(f"  ❌ {SOURCES_FILE} не содержит ни одного URL.")
        print(f"     Добавь ссылки на источники (строки с # — комментарии, игнорируются).")
        sys.exit(1)

    print(f"  📄 Загружено {len(urls)} источников из {SOURCES_FILE.name}")
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
            # нормализуем hy2:// → hysteria2://
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


def parse_host_port(uri: str):
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
# Hysteria2
# ═══════════════════════════════════════════════════════════════════════════════

def parse_hysteria2(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        return {
            "host":          p.hostname or "",
            "port":          p.port or 443,
            "auth":          p.username or p.password or "",
            "sni":           params.get("sni", p.hostname or ""),
            "insecure":      params.get("insecure", "0") == "1",
            "obfs":          params.get("obfs", ""),
            "obfs_password": params.get("obfs-password", ""),
        }
    except Exception:
        return None


def install_hysteria2() -> bool:
    if HY2_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи hysteria.exe в {HY2_BIN}")
        return False
    print("  📦 Downloading hysteria2…")
    arch = platform.machine().lower()
    fname = "hysteria-linux-arm64" if arch in ("aarch64", "arm64") else "hysteria-linux-amd64"
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
    uri = item["uri"]
    cfg = parse_hysteria2(uri)
    if not cfg:
        return None

    socks_port = item.get("_socks_port", 20100 + hash(uri) % 10000)

    hy2_config = {
        "server": f"{cfg['host']}:{cfg['port']}",
        "auth":   cfg["auth"],
        "tls":    {"sni": cfg["sni"], "insecure": cfg["insecure"]},
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
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
    hp = parse_host_port(uri)
    if not hp:
        return None
    host, port, proto_type = hp
    async with sem:
        if proto_type == "udp":
            try:
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(loop.getaddrinfo(host, port), timeout=TIMEOUT_TCP)
                return {"uri": uri, "host": host, "port": port, "tcp_ms": 0, "proto": "hysteria2"}
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


async def stage2_test(sem, idx: int, item: dict) -> dict | None:
    uri    = item["uri"]
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
            try:
                http_lat = await asyncio.wait_for(
                    _curl_through_socks(socks_port), timeout=TIMEOUT_CURL + 5
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
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n{'='*64}")
    print(f"  Proxy Checker (RU edition)  |  {ts}")
    print(f"  Протоколы: {ALLOWED_PROTOCOLS}")
    print(f"  Страны: {sorted(ALLOWED_COUNTRIES) or 'все'}")
    print(f"{'='*64}\n")

    print("📄 Loading sources…")
    SOURCES = load_sources()
    print()

    print("📥 Fetching sources…")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as s:
        batches = await asyncio.gather(*[fetch_source(s, u) for u in SOURCES])
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Unique configs: {len(all_configs)}")

    proto_counts: dict[str, int] = {}
    for c in all_configs:
        proto = c.split("://")[0].lower()
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    print("  Протоколы: " + ", ".join(f"{k}={v}" for k, v in sorted(proto_counts.items())))

    filtered = filter_configs(all_configs)
    print(f"🔎 After protocol filter: {len(filtered)}\n")
    if not filtered:
        print("⚠️  No configs after filtering.")
        return

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
    tcp_alive.sort(key=lambda x: (x["tcp_ms"] == 0, x["tcp_ms"]))
    print(f"  ✅ TCP-alive: {len(tcp_alive)}\n")

    if not tcp_alive:
        print("⚠️  No TCP-alive proxies.")
        return

    print("🛠  Preparing binaries…")
    xray_ok = install_xray()
    hy2_needed = any(i["uri"].startswith(("hysteria2://", "hy2://")) for i in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok = install_hysteria2() if hy2_needed else False

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

    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")

    # --- Генерация конфигов для Clash ---
    def to_yaml_str(obj, indent=0):
        sp = "  " * indent
        if isinstance(obj, dict):
            if not obj: return "{}"
            lines = []
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{sp}{k}:")
                    lines.append(to_yaml_str(v, indent + 1))
                else:
                    val = v
                    if isinstance(v, bool): val = str(v).lower()
                    elif isinstance(v, str): val = '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
                    lines.append(f"{sp}{k}: {val}")
            return "\n".join(lines)
        elif isinstance(obj, list):
            if not obj: return "[]"
            lines = []
            for item in obj:
                if isinstance(item, dict):
                    first = True
                    for k, v in item.items():
                        if first:
                            if isinstance(v, (dict, list)):
                                lines.append(f"{sp}- {k}:")
                                lines.append(to_yaml_str(v, indent + 2))
                            else:
                                val = v
                                if isinstance(v, bool): val = str(v).lower()
                                elif isinstance(v, str): val = '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
                                lines.append(f"{sp}- {k}: {val}")
                            first = False
                        else:
                            if isinstance(v, (dict, list)):
                                lines.append(f"{sp}  {k}:")
                                lines.append(to_yaml_str(v, indent + 2))
                            else:
                                val = v
                                if isinstance(v, bool): val = str(v).lower()
                                elif isinstance(v, str): val = '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
                                lines.append(f"{sp}  {k}: {val}")
                else:
                    val = item
                    if isinstance(item, bool): val = str(item).lower()
                    elif isinstance(item, str): val = '"' + item.replace('\\', '\\\\').replace('"', '\\"') + '"'
                    lines.append(f"{sp}- {val}")
            return "\n".join(lines)
        else:
            return str(obj)

    def parse_vless_to_clash(uri):
        p = urllib.parse.urlparse(uri)
        uuid = urllib.parse.unquote(p.username or "")
        host = p.hostname or ""
        port = p.port or 443
        params = dict(urllib.parse.parse_qsl(p.query))
        name = urllib.parse.unquote(p.fragment) or f"{host}:{port}"
        name = name.replace('"', '').replace("'", "").strip() or f"{host}:{port}"
        
        proxy = {
            "name": name,
            "type": "vless",
            "server": host,
            "port": port,
            "uuid": uuid,
            "network": params.get("type", "tcp"),
            "tls": params.get("security", "none") != "none",
            "udp": True,
        }
        if params.get("flow"): proxy["flow"] = params["flow"]
        if params.get("security") == "reality":
            proxy["reality-opts"] = {"public-key": params.get("pbk", ""), "short-id": params.get("sid", "")}
            proxy["servername"] = params.get("sni", host)
            proxy["client-fingerprint"] = params.get("fp", "chrome")
        elif params.get("security") == "tls":
            proxy["servername"] = params.get("sni", host)
            proxy["client-fingerprint"] = params.get("fp", "chrome")
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", host)}}
        elif proxy["network"] == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
        return proxy

    def parse_hy2_to_clash(uri):
        p = urllib.parse.urlparse(uri)
        auth = urllib.parse.unquote(p.username or p.password or "")
        host = p.hostname or ""
        port = p.port or 443
        params = dict(urllib.parse.parse_qsl(p.query))
        name = urllib.parse.unquote(p.fragment) or f"{host}:{port}"
        name = name.replace('"', '').replace("'", "").strip() or f"{host}:{port}"
        
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": host,
            "port": port,
            "password": auth,
            "sni": params.get("sni", host),
            "skip-cert-verify": params.get("insecure", "0") == "1",
            "udp": True,
        }
        if params.get("obfs") == "salamander":
            proxy["obfs"] = "salamander"
            proxy["obfs-password"] = params.get("obfs-password", "")
        return proxy

    proxies_list = []
    for r in top:
        uri = r["uri"]
        if uri.startswith("vless://"):
            proxies_list.append(parse_vless_to_clash(uri))
        elif uri.startswith("hysteria2://"):
            proxies_list.append(parse_hy2_to_clash(uri))

    # proxies.yaml (список прокси для proxy-provider)
    yaml_proxies = to_yaml_str({"proxies": proxies_list})
    (OUTPUT_DIR / "proxies.yaml").write_text(yaml_proxies + "\n", encoding="utf-8")

    # ru.yaml (полный конфиг с правилами)
    proxy_names = [p["name"] for p in proxies_list]
    ru_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies_list,
        "proxy-groups": [
            {"name": "Proxy", "type": "select", "proxies": ["auto", "DIRECT"] + proxy_names},
            {"name": "auto", "type": "url-test", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300}
        ],
        "rules": [
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
            "DOMAIN-KEYWORD,telegram,Proxy",
            "DOMAIN-KEYWORD,google,Proxy",
            "MATCH,Proxy"
        ]
    }
    yaml_ru = to_yaml_str(ru_config)
    (OUTPUT_DIR / "ru.yaml").write_text(yaml_ru + "\n", encoding="utf-8")

    print(f"\n📁 Сохранено в {OUTPUT_DIR}/")
    print(f"   proxies.txt      — {len(top)} URI")
    print(f"   proxies.yaml     — Clash proxy-provider")
    print(f"   ru.yaml          — Полный конфиг Clash для РФ\n")

    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        proto = r.get("proto", r["uri"].split("://")[0].lower())
        http  = f"{r['http_ms']} ms" if r.get("http_ms") else f"TCP {r['tcp_ms']} ms"
        print(f"   {i+1}. [{proto}] {r['host']}:{r['port']}  →  {http}")
    print()


if __name__ == "__main__":
    asyncio.run(main())s_b64.txt, proxies.yaml, ru.yaml для FClash
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
import yaml

from datetime import datetime, timezone
from pathlib import Path

# ── Пути ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR = REPO_ROOT / "output"

# ── Настройки ─────────────────────────────────────────────────────────────────
PROBE_URLS = [
    ("https://api.telegram.org/", [200, 404]),
    ("https://telegram.org/", [200, 301, 302]),
    ("https://cp.cloudflare.com/", [200, 204]),
    ("https://www.google.com/generate_204", [200, 204]),
]

ALLOWED_PROTOCOLS = ["vless", "hysteria2"]
REQUIRE_REALITY = True
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
        if any(p in decoded for p in ("vless://", "hysteria2://", "hy2://")):
            text = decoded
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "hysteria2://", "hy2://")):
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
# Конвертация в Clash
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

        elif scheme in ("hysteria2", "hy2"):
            if scheme == "hy2":
                uri = "hysteria2://" + uri[6:]
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            return {
                "name": name,
                "type": "hysteria2",
                "server": p.hostname,
                "port": int(p.port or 443),
                "password": p.username or "",
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
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
        p = urllib.parse.urlparse(uri)
        host = p.hostname
        port = p.port or 443
        scheme = uri.split("://")[0].lower()

        async with sem:
            if scheme == "hysteria2":
                return {"uri": uri, "host": host, "port": port, "tcp_ms": 0, "proto": "hysteria2"}
            lat = await tcp_ping(host, port)
            if lat is None:
                return None
            return {"uri": uri, "host": host, "port": port, "tcp_ms": round(lat, 1), "proto": scheme}
    except Exception:
        return None

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
            return {
                "log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                              "settings": {"auth": "noauth"}}],
                "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            }
    except Exception:
        pass
    return None

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

    tcp_alive.sort(key=lambda x: (x["tcp_ms"] == 0, x.get("tcp_ms", 9999)))
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

    # === Сохранение всех файлов ===
    uri_lines = [r["uri"] for r in top]

    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    (OUTPUT_DIR / "ru.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")   # ru.txt
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    with open(OUTPUT_DIR / "proxies.yaml", "w", encoding="utf-8") as f:
        yaml.dump(generate_proxies_yaml(top), f, allow_unicode=True, sort_keys=False)

    with open(OUTPUT_DIR / "ru.yaml", "w", encoding="utf-8") as f:
        yaml.dump(generate_ru_yaml(top), f, allow_unicode=True, sort_keys=False)

    print(f"\n✅ Успешно сохранено в {OUTPUT_DIR}/")
    print(f"   • proxies.txt")
    print(f"   • ru.txt")
    print(f"   • proxies_b64.txt")
    print(f"   • proxies.yaml")
    print(f"   • ru.yaml")
    print(f"   Всего: {len(top)} рабочих прокси\n")

    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        proto = r.get("proto", r["uri"].split("://")[0])
        ms = f"{r.get('http_ms')} ms" if r.get("http_ms") else f"TCP {r.get('tcp_ms')} ms"
        print(f" {i+1:2d}. [{proto}] {r['host']}:{r['port']} → {ms}")

if __name__ == "__main__":
    asyncio.run(main())
