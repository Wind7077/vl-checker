#!/usr/bin/env python3
"""
Proxy Checker — финальная версия, анкоры НЕ ТРОГАЮТСЯ
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
HTTP_CHECK = 1
TOP_N = 250
STAGE2_CANDIDATES = 3000
MAX_CONCURRENT_TCP = 250
MAX_CONCURRENT_HTTP = 30

TIMEOUT_TCP = 1.5
TIMEOUT_CURL = 4
TIMEOUT_XRAY_START = 0.3
TIMEOUT_HY2_START = 0.8

ALLOWED_PROTOCOLS = ["vless", "trojan", "hysteria2"]

PROBE_URLS = [
    "https://cp.cloudflare.com/",
    "https://www.google.com/generate_204",
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
    if not uri.startswith("vless://"):
        return None
    try:
        # СОХРАНЯЕМ ОРИГИНАЛ ПОЛНОСТЬЮ
        original_uri = uri
        
        # Для парсинга берём только часть без анкора
        uri_for_parse = uri.split("#")[0] if "#" in uri else uri
        
        parsed = urlparse(uri_for_parse)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        
        params = parse_qs(parsed.query)
        
        config = {
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": parsed.username or "",
                            "encryption": params.get("encryption", ["none"])[0],
                            "flow": params.get("flow", [""])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", ["tcp"])[0],
                    "security": params.get("security", ["none"])[0],
                    "wsSettings": {
                        "path": params.get("path", ["/"])[0],
                        "headers": {"Host": params.get("host", [host])[0]}
                    } if params.get("type", ["tcp"])[0] == "ws" else None,
                    "tlsSettings": {
                        "serverName": params.get("sni", [host])[0],
                        "allowInsecure": params.get("allowInsecure", ["false"])[0].lower() == "true"
                    } if params.get("security", ["none"])[0] in ["tls", "reality"] else None,
                    "realitySettings": {
                        "publicKey": params.get("pbk", [""])[0],
                        "shortId": params.get("sid", [""])[0]
                    } if params.get("security", ["none"])[0] == "reality" else None
                }
            }],
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}]
        }
        
        # Убираем None
        if config["outbounds"][0]["streamSettings"].get("wsSettings") is None:
            del config["outbounds"][0]["streamSettings"]["wsSettings"]
        if config["outbounds"][0]["streamSettings"].get("tlsSettings") is None:
            del config["outbounds"][0]["streamSettings"]["tlsSettings"]
        if config["outbounds"][0]["streamSettings"].get("realitySettings") is None:
            del config["outbounds"][0]["streamSettings"]["realitySettings"]
        
        return {
            "id": base64.b64encode(original_uri.encode()).decode()[:16],
            "proto": "vless",
            "host": host,
            "port": port,
            "uri": original_uri,  # ОРИГИНАЛ С АНКОРОМ
            "config": json.dumps(config)
        }
    except:
        return None

# ==================== ПАРСИНГ TROJAN ====================
def parse_trojan(uri: str):
    if not uri.startswith("trojan://"):
        return None
    try:
        original_uri = uri
        uri_for_parse = uri.split("#")[0] if "#" in uri else uri
        
        parsed = urlparse(uri_for_parse)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        
        params = parse_qs(parsed.query)
        
        config = {
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": parsed.username or ""
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", ["tcp"])[0],
                    "security": "tls",
                    "wsSettings": {
                        "path": params.get("path", ["/"])[0],
                        "headers": {"Host": params.get("host", [host])[0]}
                    } if params.get("type", ["tcp"])[0] == "ws" else None,
                    "tlsSettings": {
                        "serverName": params.get("sni", [host])[0],
                        "allowInsecure": params.get("allowInsecure", ["false"])[0].lower() == "true"
                    }
                }
            }],
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}]
        }
        
        if config["outbounds"][0]["streamSettings"].get("wsSettings") is None:
            del config["outbounds"][0]["streamSettings"]["wsSettings"]
        
        return {
            "id": base64.b64encode(original_uri.encode()).decode()[:16],
            "proto": "trojan",
            "host": host,
            "port": port,
            "uri": original_uri,
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
    
    uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@[a-zA-Z0-9\.\-]+:\d+'
    for match in re.finditer(uuid_pattern, text, re.IGNORECASE):
        uris.add(match.group(0))
    
    protocol_pattern = r'(vless://|trojan://|hysteria2://)[^\s<>"\'\\\n]+'
    for match in re.finditer(protocol_pattern, text):
        uris.add(match.group(0))
    
    return list(uris)

# ==================== ЗАГРУЗКА ИСТОЧНИКОВ ====================
async def fetch_sources(sources_file: str = "sources.txt"):
    if not os.path.exists(sources_file):
        print(f"File {sources_file} not found")
        return ""
    
    with open(sources_file) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    print(f"Loading {len(urls)} sources...")
    
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
                    break
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
                    break
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
    print("=" * 50)
    print(f"HTTP_CHECK = {HTTP_CHECK} ({'ON' if HTTP_CHECK else 'OFF'})")
    print(f"STAGE2_CANDIDATES = {STAGE2_CANDIDATES}")
    print("=" * 50)
    
    print("Loading sources from sources.txt...")
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
    for uri in uris[:50000]:
        if uri.startswith("vless://"):
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
        elif re.match(r'[a-f0-9]{8}-', uri, re.I):
            p = parse_vless(uri)
            if p and p["proto"] in ALLOWED_PROTOCOLS:
                proxies.append(p)
    
    print(f"Parsed {len(proxies):,} proxies")
    if not proxies:
        return
    
    print(f"TCP ping ({len(proxies)} proxies, timeout={TIMEOUT_TCP}s)...")
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
        print("No alive proxies")
        return
    
    if HTTP_CHECK:
        print(f"HTTP check enabled, testing {STAGE2_CANDIDATES} random candidates...")
        candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
        
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
            print("No working proxies after HTTP check")
            return
        
        working.sort(key=lambda x: x["tcp_ms"])
        top = working[:TOP_N]
        
        print(f"\n✅ {len(top)} working proxies found:")
        for i, p in enumerate(top[:10]):
            # Выводим хост и порт, НЕ трогаем оригинальный URI
            print(f"  {i+1}. {p['host']}:{p['port']} - {p['tcp_ms']:.0f}ms ({p['proto']})")
        if len(top) > 10:
            print(f"  ... and {len(top)-10} more")
    else:
        alive.sort(key=lambda x: x["tcp_ms"])
        top = alive[:TOP_N]
        print(f"Saving {len(top)} fastest proxies (TCP only)")
    
    Path("output").mkdir(exist_ok=True)
    
    # СОХРАНЯЕМ ОРИГИНАЛЬНЫЙ URI — С АНКОРОМ
    with open("output/proxies.txt", "w") as f:
        for p in top:
            f.write(p["uri"] + "\n")
    
    with open("output/proxies_b64.txt", "w") as f:
        for p in top:
            f.write(base64.b64encode(p["uri"].encode()).decode() + "\n")
    
    print(f"\nSaved {len(top)} proxies to output/proxies.txt")
    print("Original URIs with #comments are preserved")

if __name__ == "__main__":
    asyncio.run(main())
