#!/usr/bin/env python3
"""
Proxy Checker — оптимизирован для России (RU edition)
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

# ── ЕДИНСТВЕННЫЙ URL проверки ────────────────────────────────────────────────
# HTTP без TLS — не конфликтует с SNI Reality-прокси
# generate_204 возвращает 204 No Content — минимальный трафик
PROBE_URLS = [
    ("http://www.gstatic.com/generate_204", [200, 204]),
]

ALLOWED_PROTOCOLS   = ["vless", "hysteria2", "trojan", "ss"]
REQUIRE_REALITY     = True
ALLOWED_COUNTRIES   = set()
GEO_BATCH_SIZE      = 100

TOP_N               = 500
TIMEOUT_TCP         = 1
TIMEOUT_CURL        = 15
TIMEOUT_XRAY_START  = 1.0
MAX_CONCURRENT_TCP  = 200
MAX_CONCURRENT_HTTP = 20
STAGE2_CANDIDATES   = 2000
SOCKS_BASE_PORT     = 20000

MAX_PER_ENDPOINT    = 2
MAX_PER_UUID        = 2

HYSTERIA2_PROBE_TIMEOUT = 18

if sys.platform == "win32":
    XRAY_BIN = Path(r"C:\xray\xray.exe")
    HY2_BIN  = Path(r"C:\hysteria\hysteria.exe")
else:
    XRAY_BIN = Path("/tmp/xray-bin/xray")
    HY2_BIN  = Path("/tmp/hysteria-bin/hysteria")


def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        print(f"  ❌ Файл {SOURCES_FILE} не найден.")
        sys.exit(1)
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        print(f"  ❌ {SOURCES_FILE} не содержит ни одного URL.")
        sys.exit(1)
    print(f"  📄 Загружено {len(urls)} источников из {SOURCES_FILE.name}")
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
            userinfo = p.username or ""
            if ":" not in userinfo:
                userinfo = decode_b64(userinfo)
            return userinfo
        elif scheme == "vmess":
            try:
                raw = decode_b64(uri[len("vmess://"):])
                cfg = json.loads(raw)
                return cfg.get("id", "")
            except Exception:
                return ""
    except Exception:
        pass
    return ""


def is_ip_address(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))


def smart_deduplicate(items: list[dict], 
                       max_per_endpoint: int = MAX_PER_ENDPOINT,
                       max_per_uuid: int = MAX_PER_UUID) -> tuple[list[dict], dict]:
    stats = {
        "input": len(items),
        "after_exact_dedup": 0,
        "after_uuid_server_dedup": 0,
        "after_uuid_cdn_dedup": 0,
        "output": 0,
    }
    
    def normalize_uri(uri: str) -> str:
        try:
            p = urllib.parse.urlparse(uri)
            params = sorted(urllib.parse.parse_qsl(p.query))
            query_str = urllib.parse.urlencode(params)
            return urllib.parse.urlunparse((
                p.scheme, p.netloc, p.path, p.params, query_str, ''
            ))
        except Exception:
            return uri
    
    seen_uris = set()
    unique_items = []
    for item in items:
        norm = normalize_uri(item['uri'])
        if norm not in seen_uris:
            seen_uris.add(norm)
            unique_items.append(item)
    
    stats["after_exact_dedup"] = len(unique_items)
    
    uuid_server_groups = defaultdict(list)
    for item in unique_items:
        uuid = get_uuid_from_uri(item['uri'])
        key = (uuid, item['host'], item['port'])
        uuid_server_groups[key].append(item)
    
    after_uuid_server = []
    for key, group in uuid_server_groups.items():
        group.sort(key=lambda x: (x.get("tcp_ms", 9999) == 0, x.get("tcp_ms", 9999)))
        after_uuid_server.append(group[0])
    
    stats["after_uuid_server_dedup"] = len(after_uuid_server)
    
    uuid_groups = defaultdict(list)
    for item in after_uuid_server:
        uuid = get_uuid_from_uri(item['uri'])
        uuid_groups[uuid].append(item)
    
    after_uuid = []
    for uuid, group in uuid_groups.items():
        group.sort(key=lambda x: (x.get("tcp_ms", 9999) == 0, x.get("tcp_ms", 9999)))
        after_uuid.extend(group[:max_per_uuid])
    
    stats["after_uuid_cdn_dedup"] = len(after_uuid)
    
    endpoint_groups = defaultdict(list)
    for item in after_uuid:
        key = f"{item['host']}:{item['port']}"
        endpoint_groups[key].append(item)
    
    result = []
    for key, group in endpoint_groups.items():
        group.sort(key=lambda x: (x.get("tcp_ms", 9999) == 0, x.get("tcp_ms", 9999)))
        result.extend(group[:max_per_endpoint])
    
    result.sort(key=lambda x: (x.get("tcp_ms", 9999) == 0, x.get("tcp_ms", 9999)))
    stats["output"] = len(result)
    
    return result, stats


def yaml_str(val):
    if val is None:
        return "''"
    s = str(val)
    s = s.replace("'", "''")
    return f"'{s}'"


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
    if not sni or is_ip_address(sni):
        return host
    return sni


def uri_to_clash_proxy(uri: str, idx: int = 0) -> dict | None:
    try:
        scheme = uri.split("://")[0].lower()
        p = urllib.parse.urlparse(uri)
        params = parse_all_params(uri)
        
        try:
            port = p.port or 443
        except (ValueError, TypeError):
            port = 443
            
        host = p.hostname or ""
        if not host:
            return None
        
        proxy_name = f"{idx+1}. {host}:{port}"
        
        if scheme == "vless":
            uid = p.username or params.get("uuid", "")
            if not uid:
                try:
                    uid = uri.split("://")[1].split("@")[0]
                except Exception:
                    uid = ""
            if not uid:
                return None
            
            raw_sni = params.get("sni") or params.get("peer") or params.get("servername") or host
            sni = safe_sni(raw_sni, host)
            
            sec = params.get("security", "tls").lower()
            if sec not in ("tls", "reality", "none"):
                sec = "tls"
            
            fp = params.get("fp", "chrome")
            valid_fps = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"]
            if fp not in valid_fps:
                fp = "chrome"
            
            net = params.get("type", "tcp").lower()
            valid_nets = ["tcp", "ws", "grpc", "http", "h2", "kcp", "quic", "httpupgrade", "splithttp"]
            if net not in valid_nets:
                net = "tcp"
            
            clash_net = net
            if net in ("h2", "httpupgrade", "splithttp"):
                clash_net = "tcp"
            
            pbk = params.get("pbk", "")
            sid = params.get("sid", "")
            path = params.get("path", "/") or "/"
            host_header = params.get("host", "") or host
            serviceName = params.get("serviceName", "")
            
            flow = params.get("flow", "")
            valid_flows = ["xtls-rprx-vision", "xtls-rprx-vision-udp443",
                          "xtls-rprx-origin", "xtls-rprx-origin-udp443",
                          "xtls-rprx-direct", "xtls-rprx-direct-udp443"]
            
            if sec == "reality" and (not flow or flow not in valid_flows):
                flow = "xtls-rprx-vision"
            elif flow and flow not in valid_flows:
                flow = ""
            
            proxy = {
                "name": proxy_name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": uid,
                "network": clash_net,
                "udp": True,
                "servername": sni,
            }
            
            if sec == "reality":
                proxy["tls"] = True
                proxy["client-fingerprint"] = fp
                reality_opts = {}
                if pbk:
                    reality_opts["public-key"] = pbk
                if sid:
                    reality_opts["short-id"] = sid
                if reality_opts:
                    proxy["reality-opts"] = reality_opts
                if flow:
                    proxy["flow"] = flow
            elif sec == "tls":
                proxy["tls"] = True
                proxy["skip-cert-verify"] = True
                if flow and flow in valid_flows:
                    proxy["flow"] = flow
            else:
                proxy["tls"] = False
            
            if net == "ws":
                proxy["ws-opts"] = {"path": path, "headers": {"Host": host_header}}
            elif net == "grpc" and serviceName:
                proxy["grpc-opts"] = {"grpc-service-name": serviceName}
            
            return proxy
        
        elif scheme in ("hysteria2", "hy2"):
            auth = p.username or p.password or params.get("password", "") or params.get("auth", "")
            if not auth:
                try:
                    auth = uri.split("://")[1].split("@")[0]
                except Exception:
                    auth = ""
            
            raw_sni = params.get("sni") or params.get("peer") or host
            sni = safe_sni(raw_sni, host)
            
            insecure = params.get("insecure", "0") == "1"
            obfs = params.get("obfs", "")
            obfs_password = params.get("obfs-password", "") or params.get("obfs_password", "")
            
            proxy = {
                "name": proxy_name,
                "type": "hysteria2",
                "server": host,
                "port": port,
                "password": auth,
                "udp": True,
                "sni": sni,
                "skip-cert-verify": insecure or True,
            }
            if obfs == "salamander" and obfs_password:
                proxy["obfs"] = "salamander"
                proxy["obfs-password"] = obfs_password
            
            return proxy
        
        elif scheme == "trojan":
            password = p.username or ""
            raw_sni = params.get("sni") or params.get("peer") or host
            sni = safe_sni(raw_sni, host)
            
            net = params.get("type", "tcp").lower()
            path = params.get("path", "/") or "/"
            host_header = params.get("host", "") or host
            serviceName = params.get("serviceName", "")
            
            proxy = {
                "name": proxy_name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": password,
                "network": net,
                "udp": True,
                "sni": sni,
                "skip-cert-verify": True,
            }
            
            if net == "ws":
                proxy["ws-opts"] = {"path": path, "headers": {"Host": host_header}}
            elif net == "grpc" and serviceName:
                proxy["grpc-opts"] = {"grpc-service-name": serviceName}
            
            return proxy
        
        return None
    except Exception:
        return None


def write_clash_proxies_yaml(proxies: list[dict], path: Path):
    lines = ["proxies:"]
    for p in proxies:
        lines.append(f"  - name: {yaml_str(p['name'])}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {yaml_str(p['server'])}")
        lines.append(f"    port: {p['port']}")
        
        if 'uuid' in p:
            lines.append(f"    uuid: {yaml_str(p['uuid'])}")
        if 'password' in p:
            lines.append(f"    password: {yaml_str(p['password'])}")
        if 'servername' in p:
            lines.append(f"    servername: {yaml_str(p['servername'])}")
        if 'sni' in p:
            lines.append(f"    sni: {yaml_str(p['sni'])}")
        
        for key in ['network', 'flow', 'client-fingerprint', 'obfs', 'obfs-password']:
            if key in p and p[key]:
                lines.append(f"    {key}: {yaml_str(p[key])}")
        
        if 'skip-cert-verify' in p:
            lines.append(f"    skip-cert-verify: {'true' if p['skip-cert-verify'] else 'false'}")
        if 'udp' in p:
            lines.append(f"    udp: {'true' if p['udp'] else 'false'}")
        if 'tls' in p:
            lines.append(f"    tls: {'true' if p['tls'] else 'false'}")
        
        if 'reality-opts' in p and p['reality-opts']:
            lines.append("    reality-opts:")
            for k, v in p['reality-opts'].items():
                if v:
                    lines.append(f"      {k}: {yaml_str(v)}")
        
        if 'ws-opts' in p:
            lines.append("    ws-opts:")
            for k, v in p['ws-opts'].items():
                if isinstance(v, dict):
                    lines.append(f"      {k}:")
                    for kk, vv in v.items():
                        if vv:
                            lines.append(f"        {kk}: {yaml_str(vv)}")
                else:
                    if v:
                        lines.append(f"      {k}: {yaml_str(v)}")
        
        if 'grpc-opts' in p and p['grpc-opts']:
            has_valid = any(v for v in p['grpc-opts'].values() if v)
            if has_valid:
                lines.append("    grpc-opts:")
                for k, v in p['grpc-opts'].items():
                    if v:
                        lines.append(f"      {k}: {yaml_str(v)}")
    
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_full_clash_config(proxies: list[dict], path: Path, title: str = "All Proxies"):
    proxy_names = [yaml_str(p['name']) for p in proxies]
    top_select = proxy_names[:30]
    all_for_test = proxy_names
    
    config = f"""# Proxy Checker — Full Clash Config
# Сгенерировано автоматически, {len(proxies)} прокси

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info

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
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml', encoding='utf-8') as tmp:
        write_clash_proxies_yaml(proxies, Path(tmp.name))
        proxy_block = Path(tmp.name).read_text(encoding='utf-8').split('\n', 1)[1]
        config += proxy_block
        os.unlink(tmp.name)
    
    config += """
proxy-groups:
  - name: "SELECT"
    type: select
    proxies:
      - "AUTO"
      - "FALLBACK"
"""
    for name in top_select:
        config += f"      - {name}\n"
    config += """      - DIRECT
    
  - name: "AUTO"
    type: url-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 150
    timeout: 5000
    proxies:
"""
    for name in all_for_test:
        config += f"      - {name}\n"
    
    config += """
  - name: "FALLBACK"
    type: fallback
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    timeout: 5000
    proxies:
"""
    for name in all_for_test:
        config += f"      - {name}\n"
    
    config += """
rules:
  - GEOIP,RU,DIRECT
  - DOMAIN-SUFFIX,ru,DIRECT
  - DOMAIN-SUFFIX,su,DIRECT
  - DOMAIN-SUFFIX,rf,DIRECT
  - DOMAIN-SUFFIX,yandex.ru,DIRECT
  - DOMAIN-SUFFIX,ya.ru,DIRECT
  - DOMAIN-SUFFIX,mail.ru,DIRECT
  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,ok.ru,DIRECT
  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT
  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,telegram.org,AUTO
  - DOMAIN-SUFFIX,t.me,AUTO
  - DOMAIN-SUFFIX,telegra.ph,AUTO
  - DOMAIN-SUFFIX,telesco.pe,AUTO
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
  - MATCH,SELECT
"""
    path.write_text(config, encoding="utf-8")


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


async def _curl_through_socks(socks_port: int) -> float | None:
    """Проверяет прокси через ЕДИНСТВЕННЫЙ URL — http://www.gstatic.com/generate_204"""
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


async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(f"\n{'='*64}")
    print(f"  Proxy Checker (RU edition)  |  {ts}")
    print(f"  Протоколы: {ALLOWED_PROTOCOLS}")
    print(f"  Страны: {sorted(ALLOWED_COUNTRIES) or 'все'}")
    print(f"  Probe URL: {PROBE_URLS[0][0]}")
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
    print(f"  ✅ TCP-alive: {len(tcp_alive)}")

    if not tcp_alive:
        print("⚠️  No TCP-alive proxies.")
        return

    print(f"\n🧹 Smart Deduplication...")
    tcp_alive, dedup_stats = smart_deduplicate(tcp_alive)
    
    print(f"   Было прокси:               {dedup_stats['input']}")
    print(f"   → После точных дублей:     {dedup_stats['after_exact_dedup']} (-{dedup_stats['input'] - dedup_stats['after_exact_dedup']})")
    print(f"   → После (UUID+host:port):  {dedup_stats['after_uuid_server_dedup']} (-{dedup_stats['after_exact_dedup'] - dedup_stats['after_uuid_server_dedup']})")
    print(f"   → После (UUID на CDN):     {dedup_stats['after_uuid_cdn_dedup']} (-{dedup_stats['after_uuid_server_dedup'] - dedup_stats['after_uuid_cdn_dedup']})")
    print(f"   → Финал (host:port):       {dedup_stats['output']} (-{dedup_stats['after_uuid_cdn_dedup'] - dedup_stats['output']})")
    print(f"   Итого удалено дублей:      {dedup_stats['input'] - dedup_stats['output']} ({(dedup_stats['input'] - dedup_stats['output']) / dedup_stats['input'] * 100:.1f}%)\n")

    print("🛠  Preparing binaries…")
    xray_ok = install_xray()
    hy2_needed = any(i["uri"].startswith(("hysteria2://", "hy2://")) for i in tcp_alive[:STAGE2_CANDIDATES])
    hy2_ok = install_hysteria2() if hy2_needed else False

    candidates = tcp_alive[:STAGE2_CANDIDATES]
    http_alive = []

    if xray_ok or hy2_ok:
        print(f"\n🌐 Stage 2 – curl probe  ({len(candidates)} candidates, concurrency={MAX_CONCURRENT_HTTP})")
        print(f"   URL: {PROBE_URLS[0][0]}\n")
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
    
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")

    print(f"\n🔨 Конвертация {len(top)} прокси в Clash YAML...")
    clash_proxies = []
    failed_count = 0
    
    for i, r in enumerate(top):
        cp = uri_to_clash_proxy(r["uri"], i)
        if cp:
            clash_proxies.append(cp)
        else:
            failed_count += 1
    
    success_rate = (len(clash_proxies) / len(top) * 100) if top else 0
    print(f"  ✅ Сконвертировано: {len(clash_proxies)}/{len(top)} ({success_rate:.1f}%)")
    if failed_count > 0:
        print(f"  ❌ Отброшено: {failed_count}")
    
    if clash_proxies:
        write_full_clash_config(clash_proxies, OUTPUT_DIR / "proxies.yaml", title="All Working")
        print(f"  💾 Сохранено: proxies.yaml ({len(clash_proxies)} прокси)")

    print(f"\n📁 Сохранено в {OUTPUT_DIR}/")
    print(f"   proxies.txt      — {len(top)} URI")
    print(f"   proxies_b64.txt  — base64 подписка")
    if clash_proxies:
        print(f"   proxies.yaml     — Full Clash config ({len(clash_proxies)} прокси)\n")
    
    print("🏆 Топ 5 самых быстрых:")
    for i, r in enumerate(top[:5]):
        proto = r.get("proto", r["uri"].split("://")[0].lower())
        http  = f"{r['http_ms']} ms" if r.get("http_ms") else f"TCP {r['tcp_ms']} ms"
        print(f"   {i+1}. [{proto}] {r['host']}:{r['port']}  →  {http}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
