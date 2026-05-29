#!/usr/bin/env python3
"""
Proxy Checker — с поддержкой REALITY для vless
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
import contextlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

# ========== КОНФИГУРАЦИЯ ==========
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "800"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "200"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "15"))
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "1.0"))
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "7"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "0.5"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.0"))

ALLOWED_PROTOCOLS = os.environ.get("ALLOWED_PROTOCOLS", "vless,vmess,trojan,ss,hysteria2").split(",")
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

@contextlib.asynccontextmanager
async def managed_xray(config_path: str):
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            get_xray_path(), "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        yield proc
    finally:
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

@contextlib.asynccontextmanager
async def managed_hysteria2(config_path: str):
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            get_hysteria2_path(), "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        yield proc
    finally:
        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

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
    except Exception:
        return False, 0.0

# ========== ПАРСИНГ С ПОДДЕРЖКОЙ REALITY ==========
def parse_vless_uri(uri: str) -> Optional[Dict]:
    """Парсит vless:// URI с поддержкой REALITY параметров"""
    if not uri.startswith("vless://"):
        return None
    try:
        # Убираем vless://
        uri_content = uri[8:]
        
        # Разделяем на user@host:port и параметры
        if "#" in uri_content:
            uri_content = uri_content.split("#")[0]
        
        # Ищем параметры после ?
        if "?" in uri_content:
            base_part, query_part = uri_content.split("?", 1)
            params = parse_qs(query_part)
        else:
            base_part = uri_content
            params = {}
        
        # Извлекаем host и port
        if "@" in base_part:
            userpass, hostport = base_part.split("@", 1)
            user_id = userpass
        else:
            hostport = base_part
            user_id = ""
        
        if ":" in hostport:
            host, port_str = hostport.split(":", 1)
            port = int(port_str)
        else:
            host = hostport
            port = 443
        
        # Извлекаем параметры REALITY
        security = params.get("security", ["none"])[0]
        encryption = params.get("encryption", ["none"])[0]
        flow = params.get("flow", [""])[0]
        pbk = params.get("pbk", [""])[0]  # public key
        sid = params.get("sid", [""])[0]   # short id
        fp = params.get("fp", ["chrome"])[0]  # fingerprint
        sni = params.get("sni", [""])[0]  # server name
        
        # Базовый конфиг
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": user_id,
                            "encryption": encryption,
                            "flow": flow if flow else "xtls-rprx-vision"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": security,
                    "tlsSettings": {} if security != "reality" else {
                        "serverName": sni if sni else "www.cloudflare.com",
                        "fingerprint": fp,
                        "realitySettings": {
                            "publicKey": pbk,
                            "shortId": sid if sid else ""
                        }
                    }
                }
            }]
        }
        
        # Убираем пустые поля
        if not flow:
            del config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"]
        
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": "vless",
            "host": host,
            "port": port,
            "uri": uri,
            "config_content": json.dumps(config)
        }
    except Exception as e:
        print(f"Parse error vless: {e}")
        return None

def parse_trojan_uri(uri: str) -> Optional[Dict]:
    if not uri.startswith("trojan://"):
        return None
    try:
        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
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
                "streamSettings": {"network": "tcp", "security": "tls"}
            }],
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}]
        }
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": "trojan",
            "host": host,
            "port": port,
            "uri": uri,
            "config_content": json.dumps(config)
        }
    except Exception as e:
        print(f"Parse error trojan: {e}")
        return None

def parse_hysteria2_uri(uri: str) -> Optional[Dict]:
    if not uri.startswith("hysteria2://"):
        return None
    try:
        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port
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
    except Exception as e:
        print(f"Parse error hysteria2: {e}")
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
    except Exception:
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
    except Exception:
        return False, 0.0

# ========== HTTP ПРОВЕРКА ==========
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
            async with managed_hysteria2(str(config_path)):
                await asyncio.sleep(TIMEOUT_HY2_START)
                for url, _ in PROBE_URLS:
                    ok, elapsed = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                    if ok:
                        success_count += 1
                        total_time += elapsed
        else:
            async with managed_xray(str(config_path)):
                await asyncio.sleep(TIMEOUT_XRAY_START)
                for url, _ in PROBE_URLS:
                    ok, elapsed = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                    if ok:
                        success_count += 1
                        total_time += elapsed

        if success_count == 0:
            return None

        proxy["http_ms"] = total_time / success_count
        proxy["reliability"] = success_count / len(PROBE_URLS)
        proxy["success_count"] = success_count
        return proxy
    except Exception as e:
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
            proxies.append(proxy)
    print(f"After protocol filter ({ALLOWED_PROTOCOLS}): {len(proxies)}")

    if not proxies:
        print("No proxies to test")
        return

    # TCP пинг
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

    # Случайная выборка для Stage 2
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Selected {len(candidates)} random candidates for Stage 2")

    # HTTP проверка
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
        print("Possible reasons: wrong REALITY config, dead proxies, or xray/hy2 issues")
        return

    # Ранжирование
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
