#!/usr/bin/env python3
"""
Proxy Checker — полная версия с парсингом из sources.txt
Исправлен отбор кандидатов в Stage 2: случайная выборка, а не первые N.
Добавлена корректная очистка процессов xray/hysteria2.
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
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse

# ========== КОНФИГУРАЦИЯ (можно переопределить через ENV) ==========
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "2500"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "200"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "30"))
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "3.0"))
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "10"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "1.0"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.5"))

ALLOWED_PROTOCOLS = os.environ.get("ALLOWED_PROTOCOLS", "vless,hysteria2,trojan").split(",")
REQUIRE_REALITY = os.environ.get("REQUIRE_REALITY", "false").lower() == "true"
ALLOWED_COUNTRIES = set(filter(None, os.environ.get("ALLOWED_COUNTRIES", "").split(",")))

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

# ========== ПАРСИНГ ПРОКСИ ИЗ URI ==========
def parse_proxy_uri(uri: str) -> Optional[Dict]:
    """Преобразует URI прокси в словарь с полями: id, proto, host, port, uri, config_content."""
    if uri.startswith("vless://"):
        parsed = urlparse(uri)
        proto = "vless"
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        # Базовый конфиг для xray (для проверки достаточно)
        config = {
            "log": {"loglevel": "warning"},
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": parsed.username or "", "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls" if "security=tls" in uri else "none"
                }
            }],
            "inbounds": [{"port": 1080, "protocol": "socks", "settings": {"udp": True}}]
        }
        return {
            "id": base64.b64encode(uri.encode()).decode()[:16],
            "proto": proto,
            "host": host,
            "port": port,
            "uri": uri,
            "config_content": json.dumps(config)
        }
    elif uri.startswith("trojan://"):
        parsed = urlparse(uri)
        proto = "trojan"
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
            "proto": proto,
            "host": host,
            "port": port,
            "uri": uri,
            "config_content": json.dumps(config)
        }
    elif uri.startswith("hysteria2://"):
        parsed = urlparse(uri)
        proto = "hysteria2"
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
            "proto": proto,
            "host": host,
            "port": port,
            "uri": uri,
            "config_content": json.dumps(config)
        }
    else:
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
    except Exception:
        return None

# ========== ОСНОВНАЯ ФУНКЦИЯ ==========
async def main():
    print("Загрузка источников...")
    raw_text = await fetch_all_sources("sources.txt")
    if not raw_text:
        print("Не удалось загрузить данные из sources.txt")
        return

    # Извлекаем все URI прокси из текста
    uri_pattern = re.compile(r'(vless://|trojan://|hysteria2://|ss://|vmess://)[^\s]+')
    uris = set(uri_pattern.findall(raw_text))
    print(f"Найдено уникальных URI: {len(uris)}")

    proxies = []
    for uri in uris:
        proxy = parse_proxy_uri(uri)
        if proxy and proxy["proto"] in ALLOWED_PROTOCOLS:
            proxies.append(proxy)

    print(f"Отфильтровано по протоколам {ALLOWED_PROTOCOLS}: {len(proxies)}")

    if not proxies:
        print("Нет прокси для проверки")
        return

    # Stage 1: TCP ping
    sem = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    async def ping_one(proxy):
        async with sem:
            ok, ms = await tcp_ping(proxy["host"], proxy["port"], TIMEOUT_TCP)
            if ok:
                proxy["tcp_ms"] = ms
                return proxy
            return None

    tcp_tasks = [ping_one(p) for p in proxies]
    tcp_results = await asyncio.gather(*tcp_tasks)
    alive = [p for p in tcp_results if p is not None]
    print(f"TCP живых: {len(alive)} из {len(proxies)}")

    if not alive:
        print("Нет живых по TCP")
        return

    # ГЛАВНОЕ ИСПРАВЛЕНИЕ: случайная выборка кандидатов для Stage 2
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Отобрано {len(candidates)} кандидатов для Stage 2 (случайно)")

    # Stage 2: HTTP
    http_sem = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        async def test_one(proxy):
            async with http_sem:
                return await test_proxy_http(proxy, tmp_path)

        http_tasks = [test_one(p) for p in candidates]
        http_results = await asyncio.gather(*http_tasks)
        working = [p for p in http_results if p is not None]

    print(f"HTTP прошли: {len(working)} из {len(candidates)}")

    if not working:
        print("Нет рабочих прокси после HTTP проверки")
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

    print(f"Сохранено {len(top)} прокси в output/")

if __name__ == "__main__":
    asyncio.run(main())
