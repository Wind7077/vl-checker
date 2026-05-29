#!/usr/bin/env python3
"""
Proxy Checker — быстрая версия
"""

import asyncio
import aiohttp
import aiofiles
import base64
import json
import os
import re
import subprocess
import tempfile
import time
import random
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

# ==================== НАСТРОЙКИ ====================
TOP_N = 250
STAGE2_CANDIDATES = 800
MAX_CONCURRENT_TCP = 200
MAX_CONCURRENT_HTTP = 15

TIMEOUT_TCP = 2.0
TIMEOUT_CURL = 4
TIMEOUT_XRAY_START = 0.5
TIMEOUT_HY2_START = 1.0

ALLOWED_PROTOCOLS = ["vless", "trojan", "hysteria2"]

PROBE_URLS = [
    "https://www.mozilla.org/favicon.ico",
]

# ==================== УТИЛИТЫ ====================
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

async def run_curl(url: str, timeout: float):
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

# ==================== ПАРСИНГ VLESS ====================
def parse_vless(uri: str):
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
        allow_insecure = "allowInsecure" in params
        
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

# ==================== ПАРСИНГ TROJAN ====================
def parse_trojan(uri: str):
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
        allow_insecure = "allowInsecure" in params
        
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

# ==================== ПАРСИНГ HYSTERIA2 ====================
def parse_hysteria2(uri: str):
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

# ==================== ИЗВЛЕЧЕНИЕ URI ====================
def extract_uris(text: str):
    uris = set()
    
    # UUID@host:port формат
    uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@[a-zA-Z0-9\.\-]+:\d+'
    for match in re.finditer(uuid_pattern, text, re.IGNORECASE):
        uris.add(match.group(0))
    
    # Полные URI
    protocol_pattern = r'(vless://|trojan://|hysteria2://)[^\s<>"\'\\\n]+'
    for match in re.finditer(protocol_pattern, text):
        uris.add(match.group(0))
    
    return list(uris)

# ==================== ЗАГРУЗКА ИСТОЧНИКОВ ====================
async def fetch_sources(sources_file: str = "sources.txt"):
    if not os.path.exists(sources_file):
        return ""
    
    with open(sources_file) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            async def fetch(u):
                try:
                    async with session.get(u, timeout=30) as resp:
                        if resp.status == 200:
                            return await resp.text()
                        return ""
                except:
                    return ""
            tasks.append(fetch(url))
        
        results = await asyncio.gather(*tasks)
    
    return "\n".join(results)

# ==================== TCP ПИНГ ====================
async def tcp_ping(host: str, port: int, timeout: float):
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

# ==================== HTTP ПРОВЕРКА ====================
async def test_http(proxy: dict, tmpdir: Path):
    config_path = tmpdir / f"c_{proxy['id']}.json"
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

# ==================== MAIN ====================
async def main():
    print("Loading sources...")
    raw = await fetch_sources("sources.txt")
    if not raw:
        print("No data")
        return
    print(f"Loaded {len(raw):,} chars")
    
    print("Extracting URIs...")
    uris = extract_uris(raw)
    print(f"Found {len(uris):,} URIs")
    if not uris:
        return
    
    print("Parsing...")
    proxies = []
    for uri in uris[:10000]:
        if uri.startswith("vless://") or re.match(r'[a-f0-9]{8}-', uri, re.I):
            p = parse_vless(uri)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
        elif uri.startswith("trojan://"):
            p = parse_trojan(uri)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
        elif uri.startswith("hysteria2://"):
            p = parse_hysteria2(uri)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
    
    print(f"Parsed {len(proxies):,} proxies")
    if not proxies:
        return
    
    print(f"TCP ping ({len(proxies)} proxies)...")
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
    print(f"TCP alive: {len(alive):,}")
    if not alive:
        return
    
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Testing {len(candidates)} candidates with HTTP...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        async def test(p):
            async with sem2:
                return await test_http(p, tmp_path)
        
        working = await asyncio.gather(*[test(p) for p in candidates])
        working = [p for p in working if p]
    
    print(f"HTTP passed: {len(working)}/{len(candidates)}")
    if not working:
        return
    
    for p in working:
        p["score"] = 0.3 * p["tcp_ms"] + 1.0 * p["http_ms"] - 300 * p["reliability"]
    
    working.sort(key=lambda x: x["score"])
    top = working[:TOP_N]
    
    Path("output").mkdir(exist_ok=True)
    with open("output/proxies.txt", "w") as f:
        for p in top:
            f.write(p["uri"] + "\n")
    
    with open("output/proxies_b64.txt", "w") as f:
        for p in top:
            f.write(base64.b64encode(p["uri"].encode()).decode() + "\n")
    
    print(f"Saved {len(top)} proxies to output/")

if __name__ == "__main__":
    asyncio.run(main())
