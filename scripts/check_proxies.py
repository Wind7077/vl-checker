#!/usr/bin/env python3
"""
ULTRA FAST proxy checker for Russia
Не использует xray для каждого прокси - только быстрые HTTP проверки
"""

import asyncio
import aiohttp
import base64
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Конфигурация
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
]

TIMEOUT_TOTAL = 8  # Всего 8 секунд на прокси (вместо 25+)
MAX_CONCURRENT = 200  # 200 параллельных проверок (вместо 25)
TOP_N = 100
OUTPUT_DIR = Path("output")

# Быстрая проверка - только 2 URL
TEST_URLS = [
    "http://ipinfo.io/ip",  # 0.5-1 сек
    "https://www.yandex.ru",  # 1-2 сек
]

def decode_b64(data: str) -> str:
    data = data.strip()
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except:
        return data

def extract_configs(text: str) -> List[str]:
    if re.match(r'^[A-Za-z0-9+/\n\r=]{60,}$', text.strip()):
        decoded = decode_b64(text)
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://")):
            text = decoded
    
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://")):
            configs.append(line)
    return configs

def parse_host_port(uri: str):
    try:
        import urllib.parse
        p = urllib.parse.urlparse(uri)
        return p.hostname, p.port if p.port else 443
    except:
        return None, None

async def check_proxy_fast(uri: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    """БЫСТРАЯ проверка - НЕ использует xray, только прямой HTTP через прокси"""
    host, port = parse_host_port(uri)
    if not host or not port:
        return None
    
    # Пропускаем обычные HTTP прокси
    if uri.startswith("http://"):
        return None
    
    # Прокси-URL для aiohttp (поддерживает HTTP/HTTPS прокси)
    proxy_url = f"http://{host}:{port}"  # aiohttp умеет работать с HTTP прокси
    
    best_latency = None
    
    for url in TEST_URLS:
        t0 = time.monotonic()
        try:
            async with session.get(
                url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_TOTAL),
                ssl=False,
                allow_redirects=True
            ) as resp:
                # Успешный ответ (200, 204, 301, 302 или даже 403)
                if resp.status in (200, 204, 301, 302, 403):
                    latency = (time.monotonic() - t0) * 1000
                    if best_latency is None or latency < best_latency:
                        best_latency = latency
                    break  # Успех - выходим
        except:
            continue
    
    if best_latency:
        return {
            "uri": uri,
            "host": host,
            "port": port,
            "latency_ms": round(best_latency, 1)
        }
    return None

async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    url = re.sub(r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
                 r'raw.githubusercontent.com/\1/\2/refs/heads/\3', url)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                text = await resp.text(encoding="utf-8", errors="ignore")
                configs = extract_configs(text)
                print(f"  ✓ {url[:60]} → {len(configs)} configs")
                return configs
    except Exception as e:
        print(f"  ✗ {url[:60]} → {str(e)[:30]}")
    return []

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    print(f"\n{'='*60}")
    print(f"  ULTRA FAST Proxy Checker (Russia optimized)")
    print(f"  {ts}")
    print(f"{'='*60}\n")
    
    # 1. Загрузка источников
    print("📥 Загрузка источников...")
    connector = aiohttp.TCPConnector(ssl=False, limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        batches = await asyncio.gather(*[fetch_source(session, u) for u in SOURCES])
    
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Уникальных конфигов: {len(all_configs)}")
    
    if not all_configs:
        print("⚠️ Нет конфигов")
        return
    
    # 2. БЫСТРАЯ проверка (200 параллельных запросов)
    print(f"\n⚡ БЫСТРАЯ проверка {len(all_configs)} прокси...")
    print(f"   {MAX_CONCURRENT} параллельных соединений, таймаут {TIMEOUT_TOTAL} сек")
    
    working = []
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    
    async def check_with_sem(uri):
        async with sem:
            return await check_proxy_fast(uri, session)
    
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=MAX_CONCURRENT),
        headers={'User-Agent': 'Mozilla/5.0'}
    ) as session:
        tasks = [check_with_sem(uri) for uri in all_configs]
        
        done = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            done += 1
            if result:
                working.append(result)
            
            # Прогресс каждые 500 прокси
            if done % 500 == 0:
                print(f"  … {done}/{len(all_configs)} проверено, найдено: {len(working)}")
    
    print(f"\n✅ Рабочих прокси: {len(working)}")
    
    if not working:
        print("⚠️ Нет рабочих прокси")
        return
    
    # 3. Сортировка и сохранение
    working.sort(key=lambda x: x["latency_ms"])
    top = working[:TOP_N]
    
    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n")
    
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64)
    
    report = {
        "updated": ts,
        "total": len(all_configs),
        "working": len(working),
        "saved": len(top),
        "proxies": top
    }
    (OUTPUT_DIR / "report.json").write_text(json.dumps(report, indent=2))
    
    print(f"\n📁 Сохранено {len(top)} прокси в {OUTPUT_DIR}/")
    print("\n🏆 Топ-5:")
    for i, r in enumerate(top[:5]):
        print(f"   {i+1}. {r['host']}:{r['port']} → {r['latency_ms']} ms")
    
    elapsed = time.time() - start_time
    print(f"\n⏱️  Общее время: {elapsed:.1f} секунд")

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main())
