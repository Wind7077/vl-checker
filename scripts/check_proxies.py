#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
Поддерживаемые протоколы: vless, trojan, hysteria2
Источники: sources.txt рядом со скриптом (одна строка = один URL, # = комментарий)
Выходные файлы:
  proxies.txt   — не-RU URI
  ru.txt        — RU URI
  proxies.yaml  — не-RU Clash Meta / FClash подписка (proxy-provider format)
  ru.yaml       — RU Clash Meta / FClash подписка (proxy-provider format)
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

# ── Пути ──────────────────────────────────────────────────────────────[...]
SCRIPT_DIR   = Path(__file__).parent
REPO_ROOT    = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR   = REPO_ROOT / "output"

# ── Probe-URL ────────────────────────────────────────────────────────────[...]
PROBE_URLS = [
    ("https://cp.cloudflare.com/",          [200, 204]),
    ("https://ip.sb/",                      [200]),
    ("https://ifconfig.me/ip",              [200]),
]

# ── Настройки ────────────────────────────────────────────────────────────[...]
ALLOWED_PROTOCOLS  = ["vless", "hysteria2", "trojan"]
REQUIRE_REALITY    = False
TOP_N              = 250

TIMEOUT_TCP        = 1
TIMEOUT_CURL       = 8
TIMEOUT_XRAY_START = 0.5
MAX_CONCURRENT_TCP  = 200
MAX_CONCURRENT_HTTP = 30
STAGE2_CANDIDATES  = 2000
SOCKS_BASE_PORT    = 20000

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    import shutil as _shutil
    XRAY_BIN = Path(_shutil.which("xray") or "/tmp/xray-bin/xray")
    HY2_BIN  = Path(_shutil.which("hysteria2") or "/tmp/hysteria-bin/hysteria")


# ══════════════════════════════════════════════════════════════════[...]
# Загрузка sources.txt
# ══════════════════════════════════════════════════════════════════[...]

def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        print(f"  ❌ {SOURCES_FILE} не найден"); sys.exit(1)
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        print(f"  ❌ {SOURCES_FILE} пустой"); sys.exit(1)
    print(f"  📄 {len(urls)} источников из {SOURCES_FILE.name}")
    return urls


# ══════════════════════════════════════════════════════════════════[...]
# Helpers
# ══════════════════════════════════════════════════════════════════[...]

def decode_b64(data: str) -> str:
    data = data.strip()
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="ignore")
    except Exception:
        return data


def extract_configs(text: str) -> list[str]:
    stripped = text.strip()
    if re.match(r'^[A-Za-z0-9+/\n\r=]{60,}$', stripped):
        decoded = decode_b64(stripped)
        if any(p in decoded for p in ("vless://", "trojan://", "hysteria2://", "hy2://")):
            text = decoded
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("hy2://"):
            line = "hysteria2://" + line[6:]
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")):
            result.append(line)
    return result


# ── Дедупликация по uuid+pbk (IP-фермы) ──────────────────────────────────────

def _is_junk_value(v: str) -> bool:
    v = v.strip()
    return (v.startswith("@") or v.startswith("Join") or v.startswith("Telegram")
            or "---" in v or ("@" in v and v.count("@") > 1))

def _server_fingerprint(uri: str) -> str | None:
    try:
        scheme = uri.split("://")[0].lower()
        if scheme not in ("vless", "trojan"): return None
        p = urllib.parse.urlparse(uri)
        uid = p.username or ""
        if not uid or len(uid) < 8: return None
        params = dict(urllib.parse.parse_qsl(p.query))
        pbk = params.get("pbk", "")
        if scheme == "trojan": return f"trojan:{uid}:{p.port}"
        if not pbk: return None
        return f"vless:{uid}:{pbk}"
    except Exception:
        return None

def _uri_key(uri: str) -> str:
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        params = {k: v for k, v in urllib.parse.parse_qsl(p.query)
                  if not _is_junk_value(v) and k.lower() not in ("telegram","servisename","pqv")}
        q = urllib.parse.urlencode(sorted(params.items()))
        return f"{scheme}://{p.username}@{p.hostname}:{p.port}?{q}"
    except Exception:
        return uri

def dedup_configs(configs: list[str]) -> tuple[list[str], int, int]:
    seen_uri: set[str] = set()
    after_l1: list[str] = []
    for uri in configs:
        key = _uri_key(uri)
        if key not in seen_uri:
            seen_uri.add(key)
            after_l1.append(uri)
    removed_l1 = len(configs) - len(after_l1)

    seen_fp: set[str] = set()
    after_l2: list[str] = []
    for uri in after_l1:
        fp = _server_fingerprint(uri)
        if fp is None:
            after_l2.append(uri)
        elif fp not in seen_fp:
            seen_fp.add(fp)
            after_l2.append(uri)
    removed_l2 = len(after_l1) - len(after_l2)
    return after_l2, removed_l1, removed_l2


def filter_configs(configs: list[str]) -> list[str]:
    out = []
    for uri in configs:
        scheme = uri.split("://")[0].lower()
        if ALLOWED_PROTOCOLS and scheme not in ALLOWED_PROTOCOLS: continue
        if REQUIRE_REALITY and scheme == "vless" and "reality" not in uri.lower(): continue
        out.append(uri)
    return out


def parse_host_port(uri: str) -> tuple | None:
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        host, port = p.hostname, p.port
        if not host or not port: return None
        return host, port, ("udp" if scheme == "hysteria2" else "tcp")
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════[...]
# Clash YAML builder (proxy-provider format)
# ══════════════════════════════════════════════════════════════════[...]

def _qs(val: str) -> str:
    """Значение в YAML-совместимый формат (двойные кавычки через json.dumps)."""
    return json.dumps(str(val), ensure_ascii=False)


def _clash_proxy_from_uri(name: str, uri: str) -> dict | None:
    """Конвертирует proxy URI в Clash Meta proxy dict."""
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))

        if scheme == "vless":
            host = p.hostname or ""
            port = p.port or 443
            uid  = p.username or ""
            net  = params.get("type", "tcp")
            sec  = params.get("security", "none")
            flow = params.get("flow", "")
            sni  = params.get("sni", params.get("peer", host))
            fp   = params.get("fp", "chrome")

            proxy: dict = {
                "name":   name,
                "type":   "vless",
                "server": host,
                "port":   port,
                "uuid":   uid,
                "udp":    True,
            }
            if net and net not in ("tcp", "raw"):
                proxy["network"] = net
            if flow:
                proxy["flow"] = flow
            if sec == "reality":
                proxy["tls"] = True
                proxy["servername"] = sni
                proxy["client-fingerprint"] = fp
                proxy["reality-opts"] = {
                    "public-key": params.get("pbk", ""),
                    "short-id":   params.get("sid", ""),
                }
            elif sec == "tls":
                proxy["tls"] = True
                proxy["servername"] = sni
                proxy["client-fingerprint"] = fp
                proxy["skip-cert-verify"] = True
            if net == "ws":
                proxy["ws-opts"] = {
                    "path":    params.get("path", "/"),
                    "headers": {"Host": params.get("host", host)},
                }
            elif net == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
            return proxy

        elif scheme == "trojan":
            host = p.hostname or ""
            port = p.port or 443
            sni  = params.get("sni", host)
            net  = params.get("type", "tcp")
            proxy = {
                "name":             name,
                "type":             "trojan",
                "server":           host,
                "port":             port,
                "password":         p.username or "",
                "sni":              sni,
                "skip-cert-verify": True,
                "udp":              True,
            }
            if net == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path":    params.get("path", "/"),
                    "headers": {"Host": params.get("host", host)},
                }
            elif net == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
            return proxy

        elif scheme == "hysteria2":
            host = p.hostname or ""
            port = p.port or 443
            auth = p.username or p.password or ""
            sni  = params.get("sni", host)
            proxy = {
                "name":             name,
                "type":             "hysteria2",
                "server":           host,
                "port":             port,
                "password":         auth,
                "sni":              sni,
                "skip-cert-verify": params.get("insecure", "0") == "1",
                "udp":              True,
            }
            if params.get("obfs") == "salamander":
                proxy["obfs"] = "salamander"
                proxy["obfs-password"] = params.get("obfs-password", "")
            return proxy

    except Exception:
        return None
    return None


def _write_proxy_to_yaml(proxy: dict, indent: int = 2) -> str:
    """Сериализует proxy dict в YAML block-style (без pyyaml)."""
    pad = " " * indent
    lines = [f'{pad}- name: {_qs(proxy["name"])}']
    
    for k, v in proxy.items():
        if k == "name":
            continue
        if isinstance(v, dict):
            # Вложенный dict
            lines.append(f'{pad}  {k}:')
            for dk, dv in v.items():
                if isinstance(dv, dict):  # headers в ws-opts
                    lines.append(f'{pad}    {dk}:')
                    for hk, hv in dv.items():
                        lines.append(f'{pad}      {hk}: {_qs(str(hv))}')
                else:
                    lines.append(f'{pad}    {dk}: {_qs(str(dv))}')
        else:
            # Скалярное значение
            if isinstance(v, bool):
                val = "true" if v else "false"
            elif isinstance(v, int):
                val = str(v)
            else:
                val = _qs(str(v))
            lines.append(f'{pad}  {k}: {val}')
    
    return "\n".join(lines)


def build_provider_yaml(items: list[dict]) -> str:
    """Строит Clash proxy-provider YAML (только секция proxies:)."""
    proxies: list[dict] = []
    
    for i, item in enumerate(items):
        uri   = item["uri"]
        proto = item.get("proto", uri.split("://")[0].lower())
        host  = item.get("host", "")
        ms    = item.get("http_ms")
        ms_str = f"{ms}ms-" if ms else ""
        name  = f"{proto.upper()}-{i+1:03d}-{ms_str}{host}"[:60]
        
        clash_proxy = _clash_proxy_from_uri(name, uri)
        if clash_proxy:
            proxies.append(clash_proxy)
    
    if not proxies:
        return "proxies: []\n"
    
    proxy_blocks = "\n".join(_write_proxy_to_yaml(p) for p in proxies)
    
    return f"proxies:\n{proxy_blocks}\n"


# ══════════════════════════════════════════════════════════════════[...]
# Fetch sources  (стриминг, лимит 20MB)
# ══════════════════════════════════════════════════════════════════[...]

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    url = re.sub(r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
                 r'raw.githubusercontent.com/\1/\2/refs/heads/\3', url)
    MAX_BYTES = 20 * 1024 * 1024
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                print(f"  ✗ HTTP {resp.status}  {url[:70]}")
                return []
            chunks, total = [], 0
            async for chunk in resp.content.iter_chunked(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BYTES:
                    break
            text = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ✗ {type(e).__name__}  {url[:70]}")
        return []
    configs = extract_configs(text)
    trunc = " ⚠️ обрезан" if total >= MAX_BYTES else ""
    print(f"  ✓ {len(configs):5d} конфигов{trunc}  {url[:65]}")
    return configs


# ══════════════════════════════════════════════════════════════════[...]
# Stage 1 — TCP-ping / DNS-resolve
# ══════════════════════════════════════════════════════════════════[...]

async def tcp_ping(host: str, port: int) -> float | None:
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT_TCP)
        ms = round((time.monotonic() - t0) * 1000, 1)
        w.close()
        try: await w.wait_closed()
        except: pass
        return ms
    except Exception:
        return None


async def stage1_worker(sem: asyncio.Semaphore, uri: str) -> dict | None:
    hp = parse_host_port(uri)
    if not hp: return None
    host, port, proto_type = hp
    proto = uri.split("://")[0].lower()
    async with sem:
        if proto_type == "udp":
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().getaddrinfo(host, port), timeout=TIMEOUT_TCP
                )
                return {"uri": uri, "host": host, "port": port, "tcp_ms": None, "proto": proto}
            except:
                return None
        else:
            ms = await tcp_ping(host, port)
            if ms is None: return None
            return {"uri": uri, "host": host, "port": port, "tcp_ms": ms, "proto": proto}


# ══════════════════════════════════════════════════════════════════[...]
# Установка бинарей
# ══════════════════════════════════════════════════════════════════[...]

def _download(url: str, dest: Path) -> bool:
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  ✗ download: {e}"); return False

def install_xray() -> bool:
    if XRAY_BIN.exists(): return True
    if sys.platform == "win32": return False
    print("  📦 Downloading xray-core…")
    arch  = platform.machine().lower()
    fname = "Xray-linux-arm64-v8a.zip" if arch in ("aarch64","arm64") else "Xray-linux-64.zip"
    tmp   = Path("/tmp/xray.zip")
    if not _download(f"https://github.com/XTLS/Xray-core/releases/latest/download/{fname}", tmp):
        return False
    try:
        with zipfile.ZipFile(tmp) as z: z.extractall(XRAY_BIN.parent)
        XRAY_BIN.chmod(0o755); print("  ✓ xray-core ready"); return True
    except Exception as e:
        print(f"  ✗ xray unzip: {e}"); return False

def install_hysteria2() -> bool:
    if HY2_BIN.exists(): return True
    if sys.platform == "win32": return False
    print("  📦 Downloading hysteria2…")
    arch  = platform.machine().lower()
    fname = "hysteria-linux-arm64" if arch in ("aarch64","arm64") else "hysteria-linux-amd64"
    if not _download(f"https://github.com/apernet/hysteria/releases/latest/download/{fname}", HY2_BIN):
        return False
    HY2_BIN.chmod(0o755); print("  ✓ hysteria2 ready"); return True


# ══════════════════════════════════════════════════════════════════[...]
# Stage 2 — curl через SOCKS5
# ══════════════════════════════════════════════════════════════════[...]

async def curl_probe(socks_port: int) -> float | None:
    for url, ok_codes in PROBE_URLS:
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                "--max-time", str(TIMEOUT_CURL),
                "--connect-timeout", "4",
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


def make_xray_config(uri: str, socks_port: int) -> dict | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vless":
            p      = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            host, port = p.hostname or "", p.port or 443
            net, sec = params.get("type", "tcp"), params.get("security", "none")
            sni = params.get("sni", params.get("peer", host))
            sid = params.get("sid", "").strip().lower()
            ob = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [{
                    "id": p.username or "", "encryption": "none",
                    "flow": params.get("flow", ""),
                }]}]},
                "streamSettings": {"network": net if net not in ("raw","xhttp") else "tcp"},
            }
            ss = ob["streamSettings"]
            if sec == "reality":
                if not params.get("pbk"):
                    return None
                # sid: пустая строка валидна; непустая должна быть hex чётной длины ≤16 символов
                if sid and (len(sid) % 2 != 0
                            or not re.match(r'^[0-9a-f]+$', sid)
                            or len(sid) > 16):
                    return None
                ss["security"] = "reality"
                ss["realitySettings"] = {
                    "serverName": sni, "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk", ""), "shortId": sid,
                }
            elif sec == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": sni,
                                     "fingerprint": params.get("fp", "chrome"),
                                     "allowInsecure": True}
            if net == "ws":
                ss["wsSettings"] = {"path": params.get("path", "/"),
                                    "headers": {"Host": params.get("host", host)}}
            elif net == "grpc":
                ss["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

        elif scheme == "trojan":
            p      = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            host, port = p.hostname or "", p.port or 443
            net = params.get("type", "tcp")
            ob = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port,
                                           "password": p.username or ""}]},
                "streamSettings": {
                    "network": net if net not in ("raw","xhttp") else "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": params.get("sni", host),
                                    "allowInsecure": True},
                },
            }
            if net == "ws":
                ob["streamSettings"]["wsSettings"] = {
                    "path": params.get("path", "/"),
                    "headers": {"Host": params.get("host", host)}}
        else:
            return None
    except Exception:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [ob, {"protocol": "freedom", "tag": "direct"}],
    }


def make_hy2_config(uri: str, socks_port: int) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        cfg: dict = {
            "server": f"{p.hostname}:{p.port or 443}",
            "auth":   p.username or p.password or "",
            "tls":    {"sni": params.get("sni", p.hostname or ""),
                       "insecure": params.get("insecure", "0") == "1"},
            "socks5": {"listen": f"127.0.0.1:{socks_port}"},
        }
        if params.get("obfs") == "salamander":
            cfg["obfs"] = {"type": "salamander",
                           "salamander": {"password": params.get("obfs-password", "")}}
        return cfg
    except Exception:
        return None


async def _run_probe(cmd: list[str], cfg_path: str, socks_port: int, startup: float) -> float | None:
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(startup)
        return await asyncio.wait_for(
            curl_probe(socks_port), timeout=TIMEOUT_CURL * len(PROBE_URLS) + 5
        )
    except Exception:
        return None
    finally:
        if proc:
            try: proc.kill(); await asyncio.wait_for(proc.wait(), timeout=2)
            except: pass
        try: os.unlink(cfg_path)
        except: pass


async def stage2_worker(sem: asyncio.Semaphore, idx: int, item: dict) -> dict | None:
    proto = item["proto"]
    socks_port = SOCKS_BASE_PORT + idx
    uri = item["uri"]
    async with sem:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            if proto == "hysteria2":
                cfg = make_hy2_config(uri, socks_port)
                if cfg is None: return None
                json.dump(cfg, f)
                cmd = [str(HY2_BIN), "client", "--config", f.name]
                startup = 1.5
            else:
                cfg = make_xray_config(uri, socks_port)
                if cfg is None: return None
                json.dump(cfg, f)
                cmd = [str(XRAY_BIN), "run", "-c", f.name]
                startup = TIMEOUT_XRAY_START
            cfg_path = f.name
        http_ms = await _run_probe(cmd, cfg_path, socks_port, startup)
        if http_ms is None: return None
        return {**item, "http_ms": http_ms}


# ══════════════════════════════════════════════════════════════════[...]
# Geo lookup
# ══════════════════════════════════════════════════════════════════[...]

async def get_country(session: aiohttp.ClientSession, host: str) -> str:
    for url in [f"https://ipinfo.io/{host}/country", f"https://ip2c.org/{host}"]:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=6),
                                   headers={"User-Agent": "curl/7.88"}) as r:
                if r.status == 200:
                    text = (await r.text()).strip()
                    if len(text) == 2 and text.isalpha():
                        return text.upper()
                    parts = text.split(";")
                    if len(parts) >= 2 and len(parts[1]) == 2:
                        return parts[1].upper()
        except Exception:
            pass
    return ""


# ══════════════════════════════════════════════════════════════════[...]
# Main
# ══════════════════════════════════════════════════════════════════[...]

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n{'═'*64}")
    print(f"  Proxy Checker (RU edition) | {ts}")
    print(f"  Протоколы : {ALLOWED_PROTOCOLS}")
    print(f"  Reality   : {REQUIRE_REALITY}")
    print(f"{'═'*64}\n")

    print("📄 sources.txt…")
    sources = load_sources()
    print()

    print("📥 Fetching…")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as sess:
        batches = await asyncio.gather(*[fetch_source(sess, u) for u in sources])
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    proto_stat: dict[str, int] = {}
    for c in all_configs:
        k = c.split("://")[0].lower()
        proto_stat[k] = proto_stat.get(k, 0) + 1
    print(f"\n📋 Unique configs: {len(all_configs)}")
    print("   " + " | ".join(f"{k}={v}" for k, v in sorted(proto_stat.items())))

    filtered = filter_configs(all_configs)
    before = len(filtered)
    filtered, rem_l1, rem_l2 = dedup_configs(filtered)
    print(f"\n🔎 Фильтр: {before} → −{rem_l1} клонов → −{rem_l2} ферм = {len(filtered)} уникальных")
    if not filtered:
        print("⚠️  Нет конфигов."); return

    print(f"\n🔌 Stage 1 — TCP-ping (concurrent={MAX_CONCURRENT_TCP})…")
    sem1 = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    tcp_alive: list[dict] = []
    done = 0
    for coro in asyncio.as_completed([stage1_worker(sem1, u) for u in filtered]):
        r = await coro
        done += 1
        if r: tcp_alive.append(r)
        if done % 500 == 0:
            print(f"  … {done}/{len(filtered)} — alive: {len(tcp_alive)}")
    _prio = {"vless": 0, "trojan": 1, "hysteria2": 2}
    tcp_alive.sort(key=lambda x: (_prio.get(x["proto"], 9), x["tcp_ms"] or 0))
    print(f"  ✅ TCP-alive: {len(tcp_alive)}")

    if not tcp_alive: print("⚠️  Нет живых."); return

    print("\n🛠  Binaries…")
    xray_ok = install_xray()
    need_hy2 = any(x["proto"] == "hysteria2" for x in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok   = install_hysteria2() if need_hy2 else False

    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive: list[dict] = []

    if xray_ok or hy2_ok:
        print(f"\n🌐 Stage 2 — curl probe | {len(candidates)} кандидатов | concurrent={MAX_CONCURRENT_HTTP}")
        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        done2 = 0
        for coro in asyncio.as_completed([stage2_worker(sem2, i, it) for i, it in enumerate(candidates)]):
            r = await coro
            done2 += 1
            if r: http_alive.append(r)
            if done2 % 100 == 0 or done2 == len(candidates):
                print(f"  … {done2}/{len(candidates)} — рабочих: {len(http_alive)}")
        http_alive.sort(key=lambda x: x["http_ms"])
        wp: dict[str, int] = {}
        for r in http_alive:
            wp[r["proto"]] = wp.get(r["proto"], 0) + 1
        print(f"\n  ✅ Working: {len(http_alive)} | " + " | ".join(f"{k}={v}" for k, v in sorted(wp.items())))
    else:
        print("  ⚠️  Нет бинарей")
        for r in candidates[:TOP_N]: r["http_ms"] = None
        http_alive = candidates[:TOP_N]

    if not http_alive: print("⚠️  Нет рабочих."); return

    top = http_alive[:TOP_N * 4]

    print("\n🌍 Geo lookup…")
    unique_hosts = list({r["host"] for r in top})
    host_to_cc: dict[str, str] = {}
    geo_sem = asyncio.Semaphore(15)

    async def _bounded_geo(sess, host):
        async with geo_sem:
            return host, await get_country(sess, host)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as geo_sess:
        for host, cc in await asyncio.gather(*[_bounded_geo(geo_sess, h) for h in unique_hosts]):
            host_to_cc[host] = cc

    ru_count = sum(1 for v in host_to_cc.values() if v == "RU")
    print(f"  ✅ Определено {sum(1 for v in host_to_cc.values() if v)}/{len(unique_hosts)}, RU={ru_count}")

    def _dedup_by_host(items: list[dict]) -> list[dict]:
        seen: set[str] = set()
        result = []
        for r in items:
            if r["host"] not in seen:
                seen.add(r["host"])
                result.append(r)
        return result

    ru_items    = _dedup_by_host([r for r in top if host_to_cc.get(r["host"]) == "RU"])[:TOP_N]
    other_items = _dedup_by_host([r for r in top if host_to_cc.get(r["host"]) != "RU"])[:TOP_N]
    print(f"  🇷🇺 RU: {len(ru_items)}  |  🌐 Other: {len(other_items)}")

    def _uris(items): return "\n".join(r["uri"] for r in items) + "\n"

    (OUTPUT_DIR / "proxies.txt").write_text(_uris(other_items), encoding="utf-8")
    (OUTPUT_DIR / "ru.txt").write_text(     _uris(ru_items),    encoding="utf-8")
    (OUTPUT_DIR / "proxies_b64.txt").write_text(
        base64.b64encode("\n".join(r["uri"] for r in other_items).encode()).decode(), encoding="utf-8")
    (OUTPUT_DIR / "ru_b64.txt").write_text(
        base64.b64encode("\n".join(r["uri"] for r in ru_items).encode()).decode(), encoding="utf-8")

    # Генерация proxy-provider YAML (для type:http в Clash)
    (OUTPUT_DIR / "proxies.yaml").write_text(
        build_provider_yaml(other_items), encoding="utf-8")
    (OUTPUT_DIR / "ru.yaml").write_text(
        build_provider_yaml(ru_items), encoding="utf-8")

    print(f"\n{'─'*64}")
    print(f"📁 {OUTPUT_DIR}/")
    print(f"   proxies.txt    — {len(other_items)} URI (не-RU)")
    print(f"   ru.txt         — {len(ru_items)} URI (RU)")
    print(f"   proxies_b64.txt / ru_b64.txt — base64")
    print(f"   proxies.yaml   — {len(other_items)} прокси Clash provider (не-RU)")
    print(f"   ru.yaml        — {len(ru_items)} прокси Clash provider (RU)")

    print(f"\n🏆 Топ 5:")
    all_top = sorted(ru_items + other_items, key=lambda x: x.get("http_ms") or 9999)
    for i, r in enumerate(all_top[:5]):
        cc = host_to_cc.get(r["host"], "??")
        print(f"   {i+1}. [{r['proto']}][{cc}] {r['host']}:{r['port']}  {r.get('http_ms')}ms")
    print()


if __name__ == "__main__":
    asyncio.run(main())
