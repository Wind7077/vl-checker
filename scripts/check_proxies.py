#!/usr/bin/env python3
"""
Proxy Checker — оригинальная версия из репозитория Wind7077/vl-checker
ИСПРАВЛЕНИЕ: отбор кандидатов на Stage 2 теперь случайный (вместо первых N)
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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

# ========== КОНФИГУРАЦИЯ ==========
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "500"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "200"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "30"))
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "3.0"))
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "10"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "1.0"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.5"))

ALLOWED_PROTOCOLS = os.environ.get("ALLOWED_PROTOCOLS", "vless,hysteria2,trojan").split(",")
ALLOWED_COUNTRIES = set(filter(None, os.environ.get("ALLOWED_COUNTRIES", "").split(",")))
REQUIRE_REALITY = os.environ.get("REQUIRE_REALITY", "false").lower() == "true"

PROBE_URLS = [
    ("https://cp.cloudflare.com/", {200}),
    ("https://ip.sb/", {200}),
    ("https://ifconfig.me/ip", {200}),
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

async def run_curl(socks5_host: str, socks5_port: int, url: str, timeout: float) -> Tuple[bool, float]:
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
        "--socks5-hostname", f"{socks5_host}:{socks5_port}",
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
        return False, 0.0
    except:
        return False, 0.0

# ========== ПАРСИНГ PROXY URI ==========
def parse_vless_uri(uri: str) -> Optional[Dict]:
    if not uri.startswith("vless://"):
        return None
    try:
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
                "realitySettings": {"publicKey": pbk, "shortId": sid or ""}
            }
        elif security == "tls":
            outbound["streamSettings"]["tlsSettings"] = {"serverName": sni or host}
        
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
            "uri": uri,
            "config_content": json.dumps(config)
        }
    except:
        return None

def parse_trojan_uri(uri: str) -> Optional[Dict]:
    if not uri.startswith("trojan://"):
        return None
    try:
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
        
        outbound["streamSettings"]["tlsSettings"] = {"serverName": sni or host}
        
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
            "uri": uri,
            "config_content": json.dumps(config)
        }
    except:
        return None

def parse_hysteria2_uri(uri: str) -> Optional[Dict]:
    if not uri.startswith("hysteria2://"):
        return None
    try:
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
            "config_content": json.dumps(config)
        }
    except:
        return None

def parse_proxy_uri(uri: str) -> Optional[Dict]:
    if uri.startswith("vless://"):
        return parse_vless_uri(uri)
    if uri.startswith("trojan://"):
        return parse_trojan_uri(uri)
    if uri.startswith("hysteria2://"):
        return parse_hysteria2_uri(uri)
    return None

# ========== ЗАГРУЗКА ИСТОЧНИКОВ ==========
async def fetch_source(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=30) as resp:
            if resp.status == 200:
                return await resp.text()
    except:
        pass
    return ""

async def fetch_all_sources(sources_file: str = "sources.txt") -> str:
    if not os.path.exists(sources_file):
        print(f"Файл {sources_file} не найден")
        return ""
    with open(sources_file) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, url) for url in urls]
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

# ========== HTTP ПРОВЕРКА (STAGE 2) ==========
async def test_proxy_http(proxy: Dict, tmpdir: Path) -> Optional[Dict]:
    proto = proxy["proto"]
    config_content = proxy.get("config_content")
    if not config_content:
        return None

    config_path = tmpdir / f"config_{proxy['id']}.json"
    async with aiofiles.open(config_path, "w") as f:
        await f.write(config_content)

    success_count = 0
    total_time = 0.0

    try:
        if proto == "hysteria2":
            proc = await asyncio.create_subprocess_exec(
                get_hysteria2_path(), "-c", str(config_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.sleep(TIMEOUT_HY2_START)
            for url, _ in PROBE_URLS:
                ok, elapsed = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                if ok:
                    success_count += 1
                    total_time += elapsed
            proc.terminate()
            await proc.wait()
        else:
            proc = await asyncio.create_subprocess_exec(
                get_xray_path(), "run", "-c", str(config_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.sleep(TIMEOUT_XRAY_START)
            for url, _ in PROBE_URLS:
                ok, elapsed = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                if ok:
                    success_count += 1
                    total_time += elapsed
            proc.terminate()
            await proc.wait()

        if success_count == 0:
            return None

        proxy["http_ms"] = total_time / success_count
        proxy["reliability"] = success_count / len(PROBE_URLS)
        proxy["success_count"] = success_count
        return proxy
    except:
        return None

# ========== ОСНОВНАЯ ФУНКЦИЯ ==========
async def main():
    print("Loading sources...")
    raw_text = await fetch_all_sources("sources.txt")
    if not raw_text:
        print("No data fetched")
        return

    # Извлекаем URI
    pattern = r'(vless://|trojan://|hysteria2://)[^\s]+'
    full_uris = list(set(re.findall(pattern, raw_text)))
    print(f"Found {len(full_uris)} unique URIs")

    # Парсим
    proxies = []
    for uri in full_uris:
        proxy = parse_proxy_uri(uri)
        if proxy and proxy["proto"] in ALLOWED_PROTOCOLS:
            if REQUIRE_REALITY and proxy["proto"] == "vless":
                if "reality" not in proxy.get("config_content", "").lower():
                    continue
            proxies.append(proxy)
    
    print(f"After protocol filter ({ALLOWED_PROTOCOLS}): {len(proxies)}")

    if not proxies:
        print("No proxies to test")
        return

    # Stage 1: TCP ping
    sem = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    async def ping_one(p):
        async with sem:
            ok, ms = await tcp_ping(p["host"], p["port"], TIMEOUT_TCP)
            if ok:
                p["tcp_ms"] = ms
                return p
            return None

    tcp_tasks = [ping_one(p) for p in proxies]
    tcp_results = await asyncio.gather(*tcp_tasks)
    alive = [p for p in tcp_results if p is not None]
    print(f"TCP alive: {len(alive)}/{len(proxies)}")

    if not alive:
        print("No TCP-alive proxies")
        return

    # ========== ЕДИНСТВЕННОЕ ИСПРАВЛЕНИЕ: случайная выборка ==========
    # Было: candidates = alive[:STAGE2_CANDIDATES]
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Selected {len(candidates)} random candidates for Stage 2")

    # Stage 2: HTTP test
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        async def test_one(p):
            async with http_sem:
                return await test_proxy_http(p, tmp_path)

        http_tasks = [test_one(p) for p in candidates]
        http_results = await asyncio.gather(*http_tasks)
        working = [p for p in http_results if p is not None]

    print(f"HTTP passed: {len(working)}/{len(candidates)}")

    if not working:
        print("No working proxies after HTTP check")
        return

    # Scoring
    for p in working:
        score = 0.3 * p["tcp_ms"] + 1.0 * p["http_ms"] - 300 * p["reliability"]
        p["score"] = score
    working.sort(key=lambda x: x["score"])
    top = working[:TOP_N]

    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    with open(out_dir / "proxies.txt", "w") as f:
        for p in top:
            f.write(p["uri"] + "\n")

    with open(out_dir / "proxies_b64.txt", "w") as f:
        for p in top:
            b64 = base64.b64encode(p["uri"].encode()).decode()
            f.write(b64 + "\n")

    with open(out_dir / "report.json", "w") as f:
        json.dump(top, f, indent=2)

    print(f"Saved {len(top)} proxies to output/")

if __name__ == "__main__":
    asyncio.run(main())
