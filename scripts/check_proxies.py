#!/usr/bin/env python3
"""
Proxy Checker — Telegram Edition (fast)
Сервер → YAML для FlClash (mihomo) / Android / MTS LTE

Оптимизации:
  - Pre-dedup по host:port ДО проверок (10000 → ~2500 уникальных)
  - Фаза A: 1 быстрый пинг (отсев мёртвых)
  - Фаза B: ещё 2 пинга только для выживших (стабильность)
  - Poll порта вместо sleep(1) при старте xray
  - Concurrency 60
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
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
REPO_ROOT    = SCRIPT_DIR.parent
SOURCES_FILE = REPO_ROOT / "sources.txt"
OUTPUT_DIR   = REPO_ROOT / "output"

# ── Probe ─────────────────────────────────────────────────────────────────────
TELEGRAM_PROBE_URL = "https://api.telegram.org/bot000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/getMe"
TELEGRAM_OK_CODES  = [200, 401, 404]

ALLOWED_PROTOCOLS   = ["vless", "hysteria2"]
REQUIRE_REALITY     = True

TOP_N               = 800
TIMEOUT_TCP         = 1.5
TIMEOUT_CURL        = 7
MAX_CONCURRENT      = 60
STAGE_CANDIDATES    = 12000
SOCKS_BASE_PORT     = 20000

# Стабильность: 1 быстрый пинг (фаза A) + 2 дополнительных (фаза B)
PHASE_B_PINGS       = 2
PHASE_B_INTERVAL    = 0.15

# Дедупликация
MAX_PER_ENDPOINT    = 1
MAX_PER_UUID        = 2
MAX_PER_PASSWORD    = 5

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN  = Path("/tmp/hysteria-bin/hysteria")


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCES / PARSING (без изменений)
# ═══════════════════════════════════════════════════════════════════════════════

def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        print(f"  ❌ {SOURCES_FILE} не найден.")
        sys.exit(1)
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        sys.exit(1)
    print(f"  📄 {len(urls)} источников")
    return urls


def decode_b64(data: str) -> str:
    padded = data.strip() + "=" * (-len(data.strip()) % 4)
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


def parse_host_port(uri: str):
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        if scheme == "hysteria2":
            host, port = p.hostname, p.port or 443
            return (host, port, "udp") if host else None
        else:
            host = p.hostname
            port = p.port or (443 if scheme != "ss" else 8388)
            return (host, port, "tcp") if host else None
    except Exception:
        return None


def get_uuid_from_uri(uri: str) -> str:
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        if scheme == "vless":
            return p.username or uri.split("://")[1].split("@")[0]
        elif scheme in ("hysteria2", "hy2"):
            return p.username or p.password or uri.split("://")[1].split("@")[0]
        elif scheme == "trojan":
            return p.username or ""
        elif scheme == "ss":
            return p.password or decode_b64(p.username or "")
        elif scheme == "vmess":
            return json.loads(decode_b64(uri[8:])).get("id", "")
    except Exception:
        pass
    return ""


def is_ip_address(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))


# ═══════════════════════════════════════════════════════════════════════════════
# PRE-DEDUP: группируем по host:port ДО проверок
# ═══════════════════════════════════════════════════════════════════════════════

def pre_dedup_by_endpoint(configs: list[str]) -> list[dict]:
    """
    Группирует URI по (host, port). Для проверки берём ОДИН представитель
    на эндпоинт. После проверки результат применим ко всем URI группы.
    Это сокращает 10000 конфигов до ~2000-3000 реальных проверок.
    """
    groups = defaultdict(list)
    for uri in configs:
        hp = parse_host_port(uri)
        if hp:
            host, port, proto_type = hp
            groups[(host, port)].append(uri)

    representatives = []
    for (host, port), uris in groups.items():
        # Берём первый URI как представитель (все на одном сервере)
        representatives.append({
            "uri": uris[0],
            "host": host,
            "port": port,
            "all_uris": uris,  # все URI на этом эндпоинте
        })
    return representatives


# ═══════════════════════════════════════════════════════════════════════════════
# DEDUPLICATION (финальная, после проверок)
# ═══════════════════════════════════════════════════════════════════════════════

def smart_deduplicate(items: list[dict]) -> tuple[list[dict], dict]:
    stats = {"input": len(items), "after_exact": 0, "after_uuid": 0, "output": 0}

    def normalize_uri(uri: str) -> str:
        try:
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            if p.fragment and '=' in p.fragment:
                for k, v in urllib.parse.parse_qsl(p.fragment):
                    if k not in params:
                        params[k] = v
            return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params,
                                            urllib.parse.urlencode(sorted(params.items())), ''))
        except Exception:
            return uri

    seen = set()
    unique = []
    for item in items:
        n = normalize_uri(item['uri'])
        if n not in seen:
            seen.add(n)
            unique.append(item)
    stats["after_exact"] = len(unique)

    # UUID/password лимиты
    uuid_groups = defaultdict(list)
    for item in unique:
        uuid_groups[get_uuid_from_uri(item['uri'])].append(item)

    result = []
    for uuid, group in uuid_groups.items():
        group.sort(key=lambda x: (x.get("avg_ms", 9999), x.get("jitter_ms", 9999)))
        scheme = group[0]['uri'].split("://")[0].lower()
        limit = MAX_PER_PASSWORD if scheme in ("ss", "hysteria2") else MAX_PER_UUID
        result.extend(group[:limit])

    # host:port лимит
    ep_groups = defaultdict(list)
    for item in result:
        ep_groups[f"{item['host']}:{item['port']}"].append(item)

    final = []
    for key, group in ep_groups.items():
        group.sort(key=lambda x: (x.get("avg_ms", 9999), x.get("jitter_ms", 9999)))
        final.extend(group[:MAX_PER_ENDPOINT])

    final.sort(key=lambda x: (x.get("avg_ms", 9999), x.get("jitter_ms", 9999)))
    stats["after_uuid"] = len(result)
    stats["output"] = len(final)
    return final, stats


# ═══════════════════════════════════════════════════════════════════════════════
# CLASH YAML (mihomo / FlClash)
# ═══════════════════════════════════════════════════════════════════════════════

def yaml_str(val):
    if val is None:
        return "''"
    return f"'{str(val).replace(chr(39), chr(39)+chr(39))}'"


def parse_all_params(uri: str) -> dict:
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        if p.fragment and '=' in p.fragment:
            for k, v in urllib.parse.parse_qsl(p.fragment):
                if k not in params:
                    params[k] = v
        return params
    except Exception:
        return {}


def safe_sni(sni: str, host: str) -> str:
    return host if (not sni or is_ip_address(sni)) else sni


def uri_to_clash_proxy(uri: str, idx: int = 0) -> dict | None:
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        params = parse_all_params(uri)
        port = p.port or 443
        host = p.hostname or ""
        if not host:
            return None
        name = f"{idx+1}. {host}:{port}"

        if scheme == "vless":
            uid = p.username or ""
            if not uid:
                try: uid = uri.split("://")[1].split("@")[0]
                except: return None
            if not uid:
                return None
            sni = safe_sni(params.get("sni") or params.get("peer") or host, host)
            sec = params.get("security", "tls").lower()
            if sec not in ("tls", "reality", "none"): sec = "tls"
            fp = params.get("fp", "chrome")
            if fp not in ("chrome","firefox","safari","ios","android","edge","360","qq","random"): fp = "chrome"
            net = params.get("type", "tcp").lower()
            if net not in ("tcp","ws","grpc","http","h2","kcp","quic","httpupgrade","splithttp"): net = "tcp"
            clash_net = "tcp" if net in ("h2","httpupgrade","splithttp") else net
            flow = params.get("flow", "")
            vf = ["xtls-rprx-vision","xtls-rprx-vision-udp443","xtls-rprx-origin",
                  "xtls-rprx-origin-udp443","xtls-rprx-direct","xtls-rprx-direct-udp443"]
            if sec == "reality" and flow not in vf: flow = "xtls-rprx-vision"
            elif flow and flow not in vf: flow = ""

            proxy = {"name": name, "type": "vless", "server": host, "port": port,
                     "uuid": uid, "network": clash_net, "udp": True, "servername": sni}
            if sec == "reality":
                proxy["tls"] = True
                proxy["client-fingerprint"] = fp
                ro = {}
                if params.get("pbk"): ro["public-key"] = params["pbk"]
                if params.get("sid"): ro["short-id"] = params["sid"]
                if ro: proxy["reality-opts"] = ro
                if flow: proxy["flow"] = flow
            elif sec == "tls":
                proxy["tls"] = True
                proxy["skip-cert-verify"] = True
                if flow in vf: proxy["flow"] = flow
            else:
                proxy["tls"] = False
            if net == "ws":
                proxy["ws-opts"] = {"path": params.get("path","/"),
                                     "headers": {"Host": params.get("host", host)}}
            elif net == "grpc" and params.get("serviceName"):
                proxy["grpc-opts"] = {"grpc-service-name": params["serviceName"]}
            return proxy

        elif scheme in ("hysteria2", "hy2"):
            auth = p.username or p.password or params.get("password","") or params.get("auth","")
            if not auth:
                try: auth = uri.split("://")[1].split("@")[0]
                except: auth = ""
            sni = safe_sni(params.get("sni") or host, host)
            proxy = {"name": name, "type": "hysteria2", "server": host, "port": port,
                     "password": auth, "udp": True, "sni": sni, "skip-cert-verify": True}
            if params.get("obfs") == "salamander" and params.get("obfs-password"):
                proxy["obfs"] = "salamander"
                proxy["obfs-password"] = params["obfs-password"]
            return proxy

        elif scheme == "trojan":
            sni = safe_sni(params.get("sni") or host, host)
            net = params.get("type", "tcp").lower()
            proxy = {"name": name, "type": "trojan", "server": host, "port": port,
                     "password": p.username or "", "network": net,
                     "udp": True, "sni": sni, "skip-cert-verify": True}
            if net == "ws":
                proxy["ws-opts"] = {"path": params.get("path","/"),
                                     "headers": {"Host": params.get("host", host)}}
            elif net == "grpc" and params.get("serviceName"):
                proxy["grpc-opts"] = {"grpc-service-name": params["serviceName"]}
            return proxy

        return None
    except Exception:
        return None


def write_full_clash_config(proxies: list[dict], path: Path):
    names = [yaml_str(p['name']) for p in proxies]

    config = f"""# Proxy Checker — Telegram / FlClash (mihomo) / MTS LTE
# {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | {len(proxies)} proxies

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
unified-delay: true
external-controller: 127.0.0.1:9090
keep-alive-interval: 15
keep-alive-idle: 30

geodata-mode: true
geodata-loader: memorize
geo-auto-update: true
geo-auto-update-interval: 24
geox-url:
  geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"
  geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
  mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"
  asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"

profile:
  store-selected: true

proxies:
"""
    for p in proxies:
        config += f"  - name: {yaml_str(p['name'])}\n"
        config += f"    type: {p['type']}\n"
        config += f"    server: {yaml_str(p['server'])}\n"
        config += f"    port: {p['port']}\n"
        for k in ('uuid','password','servername','sni','cipher','network','flow',
                  'client-fingerprint','obfs','obfs-password'):
            if k in p and p[k]:
                config += f"    {k}: {yaml_str(p[k])}\n"
        if 'skip-cert-verify' in p:
            config += f"    skip-cert-verify: {'true' if p['skip-cert-verify'] else 'false'}\n"
        if 'udp' in p:
            config += f"    udp: {'true' if p['udp'] else 'false'}\n"
        if 'tls' in p:
            config += f"    tls: {'true' if p['tls'] else 'false'}\n"
        if 'reality-opts' in p and p['reality-opts']:
            config += "    reality-opts:\n"
            for k, v in p['reality-opts'].items():
                if v: config += f"      {k}: {yaml_str(v)}\n"
        if 'ws-opts' in p:
            config += "    ws-opts:\n"
            for k, v in p['ws-opts'].items():
                if isinstance(v, dict):
                    config += f"      {k}:\n"
                    for kk, vv in v.items():
                        if vv: config += f"        {kk}: {yaml_str(vv)}\n"
                elif v:
                    config += f"      {k}: {yaml_str(v)}\n"
        if 'grpc-opts' in p and p['grpc-opts']:
            config += "    grpc-opts:\n"
            for k, v in p['grpc-opts'].items():
                if v: config += f"      {k}: {yaml_str(v)}\n"

    config += """
proxy-groups:
  - name: "SELECT"
    type: select
    proxies:
      - "AUTO"
      - "FALLBACK"
"""
    for n in names[:30]:
        config += f"      - {n}\n"
    config += "      - DIRECT\n"

    config += """
  - name: "AUTO"
    type: url-test
    url: "https://api.telegram.org/bot000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/getMe"
    interval: 120
    tolerance: 80
    timeout: 4000
    proxies:
"""
    for n in names:
        config += f"      - {n}\n"

    config += """
  - name: "FALLBACK"
    type: fallback
    url: "https://api.telegram.org/bot000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/getMe"
    interval: 120
    timeout: 4000
    proxies:
"""
    for n in names:
        config += f"      - {n}\n"

    config += """
rules:
  - DOMAIN-SUFFIX,telegram.org,AUTO
  - DOMAIN-SUFFIX,t.me,AUTO
  - DOMAIN-SUFFIX,telegra.ph,AUTO
  - DOMAIN-SUFFIX,telesco.pe,AUTO
  - DOMAIN-SUFFIX,telegram.me,AUTO
  - DOMAIN-SUFFIX,telegram.dog,AUTO
  - DOMAIN-SUFFIX,tdesktop.com,AUTO
  - DOMAIN-KEYWORD,telegram,AUTO
  - IP-CIDR,91.108.4.0/22,AUTO,no-resolve
  - IP-CIDR,91.108.8.0/22,AUTO,no-resolve
  - IP-CIDR,91.108.12.0/22,AUTO,no-resolve
  - IP-CIDR,91.108.16.0/22,AUTO,no-resolve
  - IP-CIDR,91.108.20.0/22,AUTO,no-resolve
  - IP-CIDR,91.108.56.0/22,AUTO,no-resolve
  - IP-CIDR,95.161.64.0/20,AUTO,no-resolve
  - IP-CIDR,149.154.160.0/20,AUTO,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,AUTO,no-resolve
  - IP-CIDR6,2001:b28:f23f::/48,AUTO,no-resolve
  - IP-CIDR6,2a0a:a980::/64,AUTO,no-resolve
  - GEOIP,RU,DIRECT
  - DOMAIN-SUFFIX,ru,DIRECT
  - DOMAIN-SUFFIX,su,DIRECT
  - DOMAIN-SUFFIX,yandex.ru,DIRECT
  - DOMAIN-SUFFIX,ya.ru,DIRECT
  - DOMAIN-SUFFIX,mail.ru,DIRECT
  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,ok.ru,DIRECT
  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,mts.ru,DIRECT
  - DOMAIN-SUFFIX,mgts.ru,DIRECT
  - MATCH,SELECT
"""
    path.write_text(config, encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════
# XRAY / HYSTERIA2
# ═══════════════════════════════════════════════════════════════════════════════

def install_xray() -> bool:
    if XRAY_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи xray.exe в {XRAY_BIN}"); return False
    print("  📦 Downloading xray…")
    arch = platform.machine().lower()
    fname = "Xray-linux-arm64-v8a.zip" if arch in ("aarch64","arm64") else "Xray-linux-64.zip"
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{fname}"
    try:
        tmpzip = Path("/tmp/xray.zip")
        urllib.request.urlretrieve(url, tmpzip)
        XRAY_BIN.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmpzip) as z:
            z.extractall(XRAY_BIN.parent)
        XRAY_BIN.chmod(0o755)
        print("  ✓ xray ready"); return True
    except Exception as e:
        print(f"  ✗ {e}"); return False


def install_hysteria2() -> bool:
    if HY2_BIN.exists():
        return True
    if sys.platform == "win32":
        print(f"  ⚠️  Положи hysteria.exe в {HY2_BIN}"); return False
    print("  📦 Downloading hysteria2…")
    arch = platform.machine().lower()
    fname = "hysteria-linux-arm64" if arch in ("aarch64","arm64") else "hysteria-linux-amd64"
    url = f"https://github.com/apernet/hysteria/releases/latest/download/{fname}"
    try:
        HY2_BIN.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, HY2_BIN)
        HY2_BIN.chmod(0o755)
        print("  ✓ hysteria2 ready"); return True
    except Exception as e:
        print(f"  ✗ {e}"); return False


def make_xray_config(uri: str, socks_port: int) -> dict | None:
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vless":
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            uid, host, port = p.username or "", p.hostname or "", p.port or 443
            flow = params.get("flow", "")
            sni = params.get("sni", params.get("peer", host))
            fp = params.get("fp", "chrome")
            net = params.get("type", "tcp")
            sec = params.get("security", "none")
            outbound = {"protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port,
                    "users": [{"id": uid, "encryption": "none", "flow": flow}]}]},
                "streamSettings": {"network": net}}
            ss = outbound["streamSettings"]
            if sec == "reality":
                ss["security"] = "reality"
                ss["realitySettings"] = {"serverName": sni, "fingerprint": fp,
                    "publicKey": params.get("pbk",""), "shortId": params.get("sid","")}
            elif sec == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": sni, "fingerprint": fp, "allowInsecure": True}
            if net == "ws":
                ss["wsSettings"] = {"path": params.get("path","/"),
                                     "headers": {"Host": params.get("host", host)}}
            elif net == "grpc":
                ss["grpcSettings"] = {"serviceName": params.get("serviceName","")}

        elif scheme == "trojan":
            p = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(p.query))
            outbound = {"protocol": "trojan",
                "settings": {"servers": [{"address": p.hostname, "port": p.port or 443,
                                           "password": p.username or ""}]},
                "streamSettings": {"network": "tcp", "security": "tls",
                    "tlsSettings": {"serverName": params.get("sni", p.hostname), "allowInsecure": True}}}

        elif scheme == "vmess":
            cfg = json.loads(decode_b64(uri[8:]))
            outbound = {"protocol": "vmess",
                "settings": {"vnext": [{"address": cfg.get("add",""), "port": int(cfg.get("port",443)),
                    "users": [{"id": cfg.get("id",""), "alterId": int(cfg.get("aid",0)), "security": "auto"}]}]},
                "streamSettings": {"network": cfg.get("net","tcp")}}
            ss = outbound["streamSettings"]
            if cfg.get("tls") == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {"serverName": cfg.get("sni", cfg.get("host","")), "allowInsecure": True}
            if cfg.get("net") == "ws":
                ss["wsSettings"] = {"path": cfg.get("path","/"), "headers": {"Host": cfg.get("host","")}}

        elif scheme == "ss":
            p = urllib.parse.urlparse(uri)
            userinfo, password = p.username or "", p.password or ""
            if password:
                method, pwd = userinfo, password
            else:
                d = decode_b64(userinfo)
                if ":" not in d: return None
                method, pwd = d.split(":", 1)
            outbound = {"protocol": "shadowsocks",
                "settings": {"servers": [{"address": p.hostname, "port": p.port or 8388,
                                           "method": method, "password": pwd}]},
                "streamSettings": {"network": "tcp"}}
        else:
            return None
    except Exception:
        return None

    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]}


def parse_hysteria2(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        params = dict(urllib.parse.parse_qsl(p.query))
        return {"host": p.hostname or "", "port": p.port or 443,
                "auth": p.username or p.password or "",
                "sni": params.get("sni", p.hostname or ""),
                "insecure": params.get("insecure","0") == "1",
                "obfs": params.get("obfs",""),
                "obfs_password": params.get("obfs-password","")}
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# БЫСТРЫЙ ЗАПУСК XRAY (poll порта вместо sleep)
# ═══════════════════════════════════════════════════════════════════════════════

async def wait_for_port(port: int, timeout: float = 2.0) -> bool:
    """Ждём пока xray поднимет SOCKS-порт. Обычно 100-300мс."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            return True
        except Exception:
            await asyncio.sleep(0.05)
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# TELEGRAM PROBE
# ═══════════════════════════════════════════════════════════════════════════════

async def curl_telegram(socks_port: int) -> float | None:
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null",
            "--socks5-hostname", f"127.0.0.1:{socks_port}",
            "--max-time", str(TIMEOUT_CURL),
            "--connect-timeout", "4",
            "-w", "%{http_code}",
            "--insecure", "-L",
            "-A", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
            TELEGRAM_PROBE_URL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_CURL + 2)
        code = int(stdout.decode().strip() or "0")
        if code in TELEGRAM_OK_CODES:
            return round((time.monotonic() - t0) * 1000, 1)
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# ЕДИНСТВЕННЫЙ ЭТАП (две фазы внутри)
# ═══════════════════════════════════════════════════════════════════════════════

async def check_proxy(sem, idx: int, item: dict) -> list[dict] | None:
    """
    Фаза A: TCP gate + 1 пинг → мёртв? skip.
    Фаза B: ещё PHASE_B_PINGS пингов → avg/jitter.
    Возвращает список результатов для ВСЕХ URI на этом эндпоинте.
    """
    uri = item["uri"]
    host, port = item["host"], item["port"]
    scheme = uri.split("://")[0].lower()
    hp = parse_host_port(uri)
    if not hp:
        return None
    _, _, proto_type = hp

    async with sem:
        # ── TCP gate ──
        if proto_type == "udp":
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().getaddrinfo(host, port), timeout=TIMEOUT_TCP)
            except Exception:
                return None
        else:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT_TCP)
                w.close()
            except Exception:
                return None

        # ── Запуск прокси ──
        if scheme in ("hysteria2", "hy2"):
            stats = await _run_hy2(uri, idx)
        else:
            stats = await _run_xray(uri, scheme, idx)

        if stats is None:
            return None

        # ── Результат для всех URI на этом эндпоинте ──
        results = []
        for u in item["all_uris"]:
            results.append({"uri": u, "host": host, "port": port,
                           "proto": u.split("://")[0].lower(), **stats})
        return results


async def _run_xray(uri, scheme, idx) -> dict | None:
    socks_port = SOCKS_BASE_PORT + idx
    cfg = make_xray_config(uri, socks_port)
    if not cfg:
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            str(XRAY_BIN), "run", "-c", cfg_path,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Ждём порт вместо sleep(1)
        if not await wait_for_port(socks_port, timeout=2.0):
            return None

        # Фаза A: 1 пинг
        lat = await curl_telegram(socks_port)
        if lat is None:
            return None

        # Фаза B: дополнительные пинги для стабильности
        latencies = [lat]
        for _ in range(PHASE_B_PINGS):
            await asyncio.sleep(PHASE_B_INTERVAL)
            l = await curl_telegram(socks_port)
            if l is not None:
                latencies.append(l)

        return _calc_stats(latencies)
    except Exception:
        return None
    finally:
        if proc:
            try: proc.kill(); await asyncio.wait_for(proc.wait(), 1)
            except: pass
        try: os.unlink(cfg_path)
        except: pass


async def _run_hy2(uri, idx) -> dict | None:
    cfg = parse_hysteria2(uri)
    if not cfg:
        return None

    socks_port = SOCKS_BASE_PORT + 10000 + idx
    hy2_cfg = {"server": f"{cfg['host']}:{cfg['port']}", "auth": cfg["auth"],
               "tls": {"sni": cfg["sni"], "insecure": cfg["insecure"]},
               "socks5": {"listen": f"127.0.0.1:{socks_port}"}}
    if cfg["obfs"] == "salamander":
        hy2_cfg["obfs"] = {"type": "salamander", "salamander": {"password": cfg["obfs_password"]}}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(hy2_cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            str(HY2_BIN), "client", "--config", cfg_path,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if not await wait_for_port(socks_port, timeout=2.5):
            return None

        lat = await curl_telegram(socks_port)
        if lat is None:
            return None

        latencies = [lat]
        for _ in range(PHASE_B_PINGS):
            await asyncio.sleep(PHASE_B_INTERVAL)
            l = await curl_telegram(socks_port)
            if l is not None:
                latencies.append(l)

        return _calc_stats(latencies)
    except Exception:
        return None
    finally:
        if proc:
            try: proc.kill(); await asyncio.wait_for(proc.wait(), 1)
            except: pass
        try: os.unlink(cfg_path)
        except: pass


def _calc_stats(latencies: list[float]) -> dict:
    avg = round(sum(latencies) / len(latencies), 1)
    mn, mx = round(min(latencies), 1), round(max(latencies), 1)
    return {"avg_ms": avg, "min_ms": mn, "max_ms": mx,
            "jitter_ms": round(mx - mn, 1),
            "success_rate": round(len(latencies) / (1 + PHASE_B_PINGS) * 100)}


# ═══════════════════════════════════════════════════════════════════════════════
# FETCH
# ═══════════════════════════════════════════════════════════════════════════════

async def fetch_source(session, url: str) -> list:
    url = re.sub(r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
                 r'raw.githubusercontent.com/\1/\2/refs/heads/\3', url)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 200:
                text = await resp.text(encoding="utf-8", errors="ignore")
                cfgs = extract_configs(text)
                print(f"  ✓ {url[:70]}  →  {len(cfgs)}")
                return cfgs
    except Exception:
        pass
    return []


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    t_start = time.monotonic()

    print(f"\n{'='*60}")
    print(f"  Proxy Checker — Telegram / FlClash / MTS LTE")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Probe: api.telegram.org | Concurrency: {MAX_CONCURRENT}")
    print(f"{'='*60}\n")

    # Sources
    SOURCES = load_sources()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=30)) as s:
        batches = await asyncio.gather(*[fetch_source(s, u) for u in SOURCES])
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Unique: {len(all_configs)}")

    filtered = filter_configs(all_configs)
    print(f"🔎 Filtered: {len(filtered)}")
    if not filtered:
        return

    # Pre-dedup по host:port (главная оптимизация)
    endpoints = pre_dedup_by_endpoint(filtered[:STAGE_CANDIDATES])
    print(f"📍 Unique endpoints: {len(endpoints)} (из {len(filtered)} URI)")

    # Binaries
    xray_ok = install_xray()
    hy2_ok = install_hysteria2() if any(
        e["uri"].startswith(("hysteria2://","hy2://")) for e in endpoints) else False
    if not xray_ok and not hy2_ok:
        print("❌ No binaries"); return

    # ── ЕДИНСТВЕННЫЙ ЭТАП ──
    print(f"\n🚀 Checking {len(endpoints)} endpoints → Telegram API…")
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    working = []
    done = 0

    for coro in asyncio.as_completed([check_proxy(sem, i, ep) for i, ep in enumerate(endpoints)]):
        r = await coro
        done += 1
        if r:
            working.extend(r)
        if done % 200 == 0 or done == len(endpoints):
            elapsed = time.monotonic() - t_start
            print(f"  … {done}/{len(endpoints)} | working: {len(working)} | {elapsed:.0f}s")

    working.sort(key=lambda x: (x["avg_ms"], x["jitter_ms"]))
    print(f"\n✅ Working: {len(working)} ({time.monotonic()-t_start:.0f}s)")
    if not working:
        return

    # Dedup
    working, ds = smart_deduplicate(working)
    print(f"🧹 Dedup: {ds['input']} → {ds['output']}")

    top = working[:TOP_N]

    # Save
    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    (OUTPUT_DIR / "proxies_b64.txt").write_text(
        base64.b64encode("\n".join(uri_lines).encode()).decode(), encoding="utf-8")

    clash_proxies = [cp for i, r in enumerate(top) if (cp := uri_to_clash_proxy(r["uri"], i))]
    if clash_proxies:
        write_full_clash_config(clash_proxies, OUTPUT_DIR / "proxies.yaml")

    elapsed = time.monotonic() - t_start
    print(f"\n📁 {OUTPUT_DIR}/")
    print(f"   proxies.txt   — {len(top)} URI")
    print(f"   proxies.yaml  — {len(clash_proxies)} proxies (FlClash)")
    print(f"\n⏱  Total: {elapsed:.0f}s")

    print(f"\n🏆 Top 5:")
    for i, r in enumerate(top[:5]):
        print(f"   {i+1}. [{r['proto']}] {r['host']}:{r['port']}  "
              f"avg={r['avg_ms']}ms  jit={r['jitter_ms']}ms")
    print()


if __name__ == "__main__":
    asyncio.run(main())
