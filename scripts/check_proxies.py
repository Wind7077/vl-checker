#!/usr/bin/env python3
"""
Proxy Checker — финальная версия
"""

import asyncio
import aiohttp
import aiofiles
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import random
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

# ========== НАСТРОЙКИ ==========
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "1500"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "150"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "10"))
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "1.5"))
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "6"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "0.5"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.0"))

ALLOWED_PROTOCOLS = os.environ.get("ALLOWED_PROTOCOLS", "vless,trojan,hysteria2").split(",")

PROBE_URLS = [
    "https://cp.cloudflare.com/",
    "https://ip.sb/",
    "https://ifconfig.me/ip",
]

# ========== УТИЛИТЫ ==========
def get_xray_path() -> str:
    for cmd in ["./xray", "xray", "/usr/local/bin/xray"]:
        if subprocess.run(["which", cmd], capture_output=True).returncode == 0:
            return cmd
    return "xray"

def get_hysteria2_path() -> str:
    for cmd in ["./hysteria2", "hysteria2", "/usr/local/bin/hysteria2"]:
        if subprocess.run(["which", cmd], capture_output=True).returncode == 0:
            return cmd
    return "hysteria2"

async def run_curl(url: str, timeout: float) -> Tuple[bool, float]:
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
        "--socks5-hostname", "127.0.0.1:1080",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout),
        url
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout+2)
        if proc.returncode == 0:
            return True, float(stdout.decode().strip() or 0)
    except:
        pass
    return False, 0.0

# ========== ПАРСИНГ VLESS ==========
def parse_vless(uri: str) -> Optional[Dict]:
    try:
        if not uri.startswith("vless://"):
            uri = "vless://" + uri
        
        content = uri[8:]
        if "#" in content:
            content = content.split("#")[0]
        
        if "?" in content:
            base, query = content.split("?", 1)
            params = parse_qs(query)
        else:
            base, params = content, {}
        
        if "@" in base:
            user_id, hostport = base.split("@", 1)
        else:
            hostport, user_id = base, ""
        
        if ":" in hostport:
            host, port_str = hostport.split(":", 1)
            port = int(port_str.split("/")[0])
        else:
            host, port = hostport, 443
        
        security = params.get("security", ["none"])[0]
        encryption = params.get("encryption", ["none"])[0]
        flow = params.get("flow", [""])[0]
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        sni = params.get("sni", [""])[0]
        network = params.get("type", ["tcp"])[0]
        ws_path = params.get("path", [""])[0]
        ws_host = params.get("host", [""])[0]
        allow_insecure = "allowInsecure" in params or params.get("allowinsecure", ["0"])[0] == "1"
        
        if ws_path and "%" in ws_path:
            ws_path = unquote(ws_path)
        
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": user_id, "encryption": encryption}]
                }]
            },
            "streamSettings": {"network": network, "security": security}
        }
        
        if flow:
            outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow
        
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": ws_path or "/",
                "headers": {"Host": ws_host or sni or host}
            }
        
        if security == "reality" and pbk:
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": sni or "www.cloudflare.com",
                "fingerprint": fp,
                "allowInsecure": allow_insecure,
                "realitySettings": {"publicKey": pbk, "shortId": sid or ""}
            }
        elif security == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": sni or host,
                "allowInsecure": allow_insecure
            }
            if fp:
                outbound["streamSettings"]["tlsSettings"]["fingerprint"] = fp
        
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [outbound]
        }
        
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": "vless",
            "host": host,
            "port": port,
            "uri": uri if uri.startswith("vless://") else "vless://" + uri,
            "config": json.dumps(config)
        }
    except:
        return None

# ========== ПАРСИНГ TROJAN ==========
def parse_trojan(uri: str) -> Optional[Dict]:
    try:
        if not uri.startswith("trojan://"):
            uri = "trojan://" + uri
        
        content = uri[9:]
        if "#" in content:
            content = content.split("#")[0]
        
        if "?" in content:
            base, query = content.split("?", 1)
            params = parse_qs(query)
        else:
            base, params = content, {}
        
        if "@" in base:
            password, hostport = base.split("@", 1)
            password = unquote(password)
        else:
            hostport, password = base, ""
        
        if ":" in hostport:
            host, port_str = hostport.split(":", 1)
            port = int(port_str.split("/")[0])
        else:
            host, port = hostport, 443
        
        network = params.get("type", ["tcp"])[0]
        ws_path = params.get("path", [""])[0]
        ws_host = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        allow_insecure = "allowInsecure" in params or params.get("allowinsecure", ["0"])[0] == "1"
        
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": {"network": network, "security": "tls"}
        }
        
        if network == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": ws_path or "/",
                "headers": {"Host": ws_host or sni or host}
            }
        
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": sni or host,
            "allowInsecure": allow_insecure
        }
        
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [outbound]
        }
        
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": "trojan",
            "host": host,
            "port": port,
            "uri": uri if uri.startswith("trojan://") else "trojan://" + uri,
            "config": json.dumps(config)
        }
    except:
        return None

# ========== ПАРСИНГ HYSTERIA2 ==========
def parse_hysteria2(uri: str) -> Optional[Dict]:
    try:
        if not uri.startswith("hysteria2://"):
            uri = "hysteria2://" + uri
        
        parsed = urlparse(uri)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return None
        
        config = {
            "server": f"{host}:{port}",
            "auth": parsed.username or "",
            "tls": {"insecure": "insecure=1" in uri},
            "socks5": {"listen": "127.0.0.1:1080"}
        }
        
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": "hysteria2",
            "host": host,
            "port": port,
            "uri": uri,
            "config": json.dumps(config)
        }
    except:
        return None

# ========== ИЗВЛЕЧЕНИЕ ПРОКСИ ==========
def extract_all_proxy_strings(text: str) -> List[str]:
    proxies = set()
    
    uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@[a-zA-Z0-9\.\-]+:\d+'
    for match in re.finditer(uuid_pattern, text, re.IGNORECASE):
        proxies.add(match.group(0))
    
    protocol_pattern = r'(vless://|trojan://|hysteria2://)[^\s<>"\'\\\n]+'
    for match in re.finditer(protocol_pattern, text):
        proxies.add(match.group(0))
    
    return list(proxies)

# ========== ИСТОЧНИКИ ==========
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/sni/protocols/vless_sni.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part1.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_all_part3.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/configs/vless.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/configs/vless_reality.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/configs/vless_reality_tcp.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/configs/all.txt",
    "https://raw.githubusercontent.com/Chm0kes/ssclprlist/refs/heads/main/vless_reality.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/vless_reality.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2",
    "https://raw.githubusercontent.com/Argh73/VpnConfigCollector/refs/heads/main/Splitted-By-Protocol/Hysteria2.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/2.txt",
    "https://raw.githubusercontent.com/kort0881/sbornik-vless/main/hysteria2_001.txt",
    "https://raw.githubusercontent.com/kort0881/sbornik-vless/main/hy2_001.txt",
    "https://raw.githubusercontent.com/kort0881/sbornik-vless/main/subs/hysteria2_001.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/servers/hysteria2_servers.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/hy2.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/trojan.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/trojan_configs.txt",
]

async def fetch_all_sources() -> str:
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in SOURCES:
            async def fetch(u):
                try:
                    async with session.get(u, timeout=30) as resp:
                        return await resp.text() if resp.status == 200 else ""
                except:
                    return ""
            tasks.append(fetch(url))
        results = await asyncio.gather(*tasks)
    return "\n".join(results)

# ========== TCP ПИНГ ==========
async def tcp_ping(host: str, port: int, timeout: float) -> Tuple[bool, float]:
    try:
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        elapsed = time.monotonic() - start
        writer.close()
        await writer.wait_closed()
        return True, elapsed * 1000
    except:
        return False, 0.0

# ========== HTTP ПРОВЕРКА ==========
async def test_http(proxy: Dict, tmpdir: Path) -> Optional[Dict]:
    config_path = tmpdir / f"config_{proxy['id']}.json"
    async with aiofiles.open(config_path, "w") as f:
        await f.write(proxy["config"])
    
    success = 0
    total_time = 0.0
    
    try:
        if proxy["proto"] == "hysteria2":
            proc = await asyncio.create_subprocess_exec(
                get_hysteria2_path(), "-c", str(config_path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(TIMEOUT_HY2_START)
            for url in PROBE_URLS:
                ok, t = await run_curl(url, TIMEOUT_CURL)
                if ok:
                    success += 1
                    total_time += t
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except:
                proc.kill()
                await proc.wait()
        else:
            proc = await asyncio.create_subprocess_exec(
                get_xray_path(), "run", "-c", str(config_path),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(TIMEOUT_XRAY_START)
            for url in PROBE_URLS:
                ok, t = await run_curl(url, TIMEOUT_CURL)
                if ok:
                    success += 1
                    total_time += t
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except:
                proc.kill()
                await proc.wait()
        
        if success == 0:
            return None
        
        proxy["http_ms"] = total_time / success
        proxy["reliability"] = success / len(PROBE_URLS)
        return proxy
    except:
        return None

# ========== MAIN ==========
async def main():
    print("Loading sources...")
    raw = await fetch_all_sources()
    print(f"Loaded {len(raw):,} chars")
    
    print("Extracting proxy strings...")
    proxy_strings = extract_all_proxy_strings(raw)
    print(f"Found {len(proxy_strings):,} proxy strings")
    
    if not proxy_strings:
        print("No proxy strings found")
        return
    
    print("Parsing proxies...")
    proxies = []
    for ps in proxy_strings[:10000]:
        if ps.startswith("vless://") or re.match(r'[a-f0-9]{8}-', ps, re.I):
            p = parse_vless(ps)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
        elif ps.startswith("trojan://"):
            p = parse_trojan(ps)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
        elif ps.startswith("hysteria2://"):
            p = parse_hysteria2(ps)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
    
    print(f"Parsed {len(proxies):,} proxies")
    
    if not proxies:
        print("No proxies after parsing")
        return
    
    print(f"TCP ping ({len(proxies):,} proxies)...")
    sem = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    async def ping(p):
        async with sem:
            ok, ms = await tcp_ping(p["host"], p["port"], TIMEOUT_TCP)
            if ok:
                p["tcp_ms"] = ms
                return p
            return None
    
    results = await asyncio.gather(*[ping(p) for p in proxies])
    alive = [p for p in results if p]
    print(f"TCP alive: {len(alive):,} / {len(proxies):,}")
    
    if not alive:
        print("No TCP-alive proxies")
        return
    
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Selected {len(candidates)} random candidates for Stage 2")
    
    print(f"HTTP check...")
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        async def test(p):
            async with http_sem:
                return await test_http(p, tmp_path)
        
        http_results = await asyncio.gather(*[test(p) for p in candidates])
        working = [p for p in http_results if p]
    
    print(f"HTTP passed: {len(working)} / {len(candidates)}")
    
    if not working:
        print("No working proxies after HTTP check")
        return
    
    for p in working:
        p["score"] = 0.3 * p["tcp_ms"] + 1.0 * p["http_ms"] - 300 * p["reliability"]
    
    working.sort(key=lambda x: x["score"])
    top = working[:TOP_N]
    
    out = Path("output")
    out.mkdir(exist_ok=True)
    
    with open(out / "proxies.txt", "w") as f:
        for p in top:
            f.write(p["uri"] + "\n")
    
    with open(out / "proxies_b64.txt", "w") as f:
        for p in top:
            f.write(base64.b64encode(p["uri"].encode()).decode() + "\n")
    
    with open(out / "report.json", "w") as f:
        json.dump(top, f, indent=2)
    
    print(f"Saved {len(top)} proxies to output/")

if __name__ == "__main__":
    asyncio.run(main())
