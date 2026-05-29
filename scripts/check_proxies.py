#!/usr/bin/env python3
"""
Proxy Checker — восстановленная версия
Исправлен только отбор кандидатов в Stage 2 и очистка процессов.
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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ========== КОНФИГУРАЦИЯ (можно менять через ENV, но со щадящими значениями) ==========
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "2500"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "200"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "30"))
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "3.0"))   # вернул 3 секунды
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "10"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "1.0"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.5"))

# Фильтры (по умолчанию всё включено, без жёстких ограничений)
ALLOWED_PROTOCOLS = os.environ.get("ALLOWED_PROTOCOLS", "vless,hysteria2,trojan").split(",")
REQUIRE_REALITY = os.environ.get("REQUIRE_REALITY", "false").lower() == "true"
ALLOWED_COUNTRIES = set(filter(None, os.environ.get("ALLOWED_COUNTRIES", "").split(",")))

# Probe URL-ы (ваши оригинальные)
PROBE_URLS = [
    ("https://cp.cloudflare.com/", {200}),
    ("https://ip.sb/", {200}),
    ("https://ifconfig.me/ip", {200}),
]

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
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

# ========== TCP ПИНГ (Stage 1) ==========
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

# ========== HTTP ПРОВЕРКА (Stage 2) ==========
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
                for url, allowed_codes in PROBE_URLS:
                    ok, elapsed = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                    if ok:
                        success_count += 1
                        total_time += elapsed
        else:
            async with managed_xray(str(config_path)):
                await asyncio.sleep(TIMEOUT_XRAY_START)
                for url, allowed_codes in PROBE_URLS:
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

# ========== ОСНОВНАЯ ЛОГИКА ==========
async def main():
    # 1. Здесь должен быть ваш оригинальный код загрузки источников и парсинга прокси.
    #    Для примера я оставляю заглушку, но вы должны вставить сюда ВАШ реальный код.
    #    Он читает sources.txt, скачивает, извлекает URI, фильтрует, дедуплицирует.
    #    В итоге получается список прокси: [{"id":, "proto":, "host":, "port":, "uri":, "config_content":}, ...]
    
    # ВРЕМЕННО: заглушка, чтобы скрипт не падал. Замените на ваш реальный парсинг.
    proxies = []
    print("Ошибка: вы не перенесли свой код парсинга прокси! Скрипт завершён.")
    sys.exit(1)

    # 2. Фильтрация по протоколу и reality (если нужно)
    filtered = []
    for p in proxies:
        if p["proto"] not in ALLOWED_PROTOCOLS:
            continue
        if REQUIRE_REALITY and p["proto"] == "vless" and "reality" not in p.get("uri", "").lower():
            continue
        filtered.append(p)

    # 3. Stage 1: TCP пинг (с ограничением параллельности)
    sem = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    async def ping_one(proxy):
        async with sem:
            ok, ms = await tcp_ping(proxy["host"], proxy["port"], TIMEOUT_TCP)
            if ok:
                proxy["tcp_ms"] = ms
                return proxy
            return None

    tcp_tasks = [ping_one(p) for p in filtered]
    tcp_results = await asyncio.gather(*tcp_tasks)
    alive = [p for p in tcp_results if p is not None]
    print(f"TCP живых: {len(alive)} из {len(filtered)}")

    if not alive:
        print("Нет живых по TCP, выход")
        return

    # 4. Отбор кандидатов на Stage 2 — СЛУЧАЙНАЯ ВЫБОРКА (исправление главного бага)
    #    Берём min(STAGE2_CANDIDATES, len(alive)) случайных прокси.
    #    Можно добавить веса на основе пинга, но проще всего — случайно.
    candidates = random.sample(alive, min(STAGE2_CANDIDATES, len(alive)))
    print(f"Отобрано {len(candidates)} кандидатов для Stage 2 (случайно)")

    # 5. Stage 2: HTTP проверка
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

    # 6. Ранжирование (чем меньше суммарное время, тем лучше)
    for p in working:
        # score = tcp_ms*0.3 + http_ms*1.0 - reliability*300 (бонус за надёжность)
        score = 0.3 * p["tcp_ms"] + 1.0 * p["http_ms"] - 300 * p["reliability"]
        p["score"] = score

    working.sort(key=lambda x: x["score"])
    top = working[:TOP_N]

    # 7. Сохранение результатов
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
