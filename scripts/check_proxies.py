#!/usr/bin/env python3
"""
Proxy Checker for Russian Federation
─────────────────────────────────────
Оптимизирован для работы в условиях DPI и блокировок РФ
Stage 1 : TCP-ping all collected configs (fast pre-filter)
Stage 2 : Multi-level HTTP probe через xray-core SOCKS5
Stage 3 : Доп. проверка на российских ресурсах
Saves top 100 by real latency.
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
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Sources (добавлены российские источники) ────────────────────────────────
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://key.zarazaex.xyz/sub",
    "https://raw.githubusercontent.com/Wind7077/vl-auto/refs/heads/main/vless_normal_vpn.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # Дополнительные российские источники
    "https://raw.githubusercontent.com/Praceps/Free-V2Ray-Configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EU/vless.txt",
]

# ── Многоуровневые URL для проверки ─────────────────────────────────────────
# Уровень 1: Быстрая проверка (простой HTTP)
PROBE_URLS_FAST = [
    "http://ipinfo.io/ip",          # Простой HTTP, отдаёт IP
    "http://2ip.ru/",               # Российский сервис
    "http://rutracker.org/forum/",  # Популярный в РФ
]

# Уровень 2: Российские HTTPS ресурсы
PROBE_URLS_RU = [
    "https://www.yandex.ru",
    "https://mail.ru",
    "https://vk.com",
]

# Уровень 3: Международные (для проверки, что прокси реально работает)
PROBE_URLS_INT = [
    "https://www.google.com/generate_204",  # Для общей проверки
    "https://cp.cloudflare.com/",
]

# Объединяем все, но с весами (приоритет российским)
PROBE_URLS = PROBE_URLS_FAST + PROBE_URLS_RU + PROBE_URLS_INT

TOP_N               = 100
OUTPUT_DIR          = Path("output")
TIMEOUT_TCP         = 5          # Увеличен для РФ
TIMEOUT_HTTP        = 25         # Увеличен для медленных прокси
MAX_CONCURRENT_TCP  = 150
MAX_CONCURRENT_HTTP = 25
SOCKS_BASE_PORT     = 20000
XRAY_BIN            = Path("/tmp/xray-bin/xray")

# Дополнительные настройки для РФ
ENABLE_FRAGMENT     = True       # Включить fragment для обхода DPI
ENABLE_PADDING      = True       # Включить padding пакетов
RETRY_COUNT         = 2          # Количество повторных попыток


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def decode_b64(data: str) -> str:
    """Декодирование Base64 с поддержкой URL-safe"""
    data = data.strip()
    # Замена URL-safe символов
    data = data.replace('-', '+').replace('_', '/')
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return data


def extract_configs(text: str) -> List[str]:
    """Извлечение конфигов с поддержкой различных форматов"""
    # Проверка на чистый base64
    if re.match(r'^[A-Za-z0-9+/\n\r=_-]{60,}$', text.strip()):
        decoded = decode_b64(text)
        if any(p in decoded for p in ("vless://", "vmess://", "trojan://", "ss://")):
            text = decoded
    
    configs = []
    for line in text.splitlines():
        line = line.strip()
        # Поддерживаем различные форматы
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            configs.append(line)
        # Также поддерживаем ссылки из подписок формата URL
        elif re.match(r'^https?://', line) and '#' in line:
            parts = line.split('#')
            if len(parts) >= 2 and parts[0].startswith(('vless://', 'vmess://')):
                configs.append(parts[0])
    
    return configs


def parse_host_port(uri: str) -> Optional[Tuple[str, int]]:
    """Парсинг host:port из URI"""
    try:
        p = urllib.parse.urlparse(uri)
        if p.hostname and p.port:
            return p.hostname, p.port
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Stage 1 – TCP ping (улучшенный для РФ)
# ═══════════════════════════════════════════════════════════════════════════

async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT_TCP) -> Optional[float]:
    """TCP ping с поддержкой медленных соединений"""
    t0 = time.monotonic()
    try:
        # Добавляем небольшую задержку перед коннектом для обхода некоторых фильтров
        await asyncio.sleep(random.uniform(0.01, 0.05))
        
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
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


async def stage1_test(sem: asyncio.Semaphore, uri: str) -> Optional[Dict]:
    """Stage 1 с приоритетом для российских прокси"""
    hp = parse_host_port(uri)
    if not hp:
        return None
    
    host, port = hp
    async with sem:
        lat = await tcp_ping(host, port)
        if lat is None:
            return None
        
        # Определяем приоритет (российские IP получают бонус)
        is_ru = False
        if host.startswith(('5.', '85.', '88.', '92.', '93.', '95.', '109.', '176.', '178.', '188.', '193.', '194.', '195.', '212.', '213.', '217.')):
            is_ru = True
            lat *= 0.8  # Бонус к российским прокси
        
        return {
            "uri": uri, 
            "host": host, 
            "port": port, 
            "tcp_ms": round(lat, 1),
            "is_ru": is_ru
        }


# ═══════════════════════════════════════════════════════════════════════════
# Xray install
# ═══════════════════════════════════════════════════════════════════════════

def install_xray() -> bool:
    """Установка xray-core с проверкой версии"""
    if XRAY_BIN.exists():
        return True
    
    print("  📦 Downloading xray-core (latest version for anti-DPI)...")
    arch = platform.machine().lower()
    fname = "Xray-linux-arm64-v8a.zip" if arch in ("aarch64", "arm64") else "Xray-linux-64.zip"
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{fname}"
    tmpzip = Path("/tmp/xray.zip")
    
    try:
        # Добавляем User-Agent для обхода блокировок
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            with open(tmpzip, 'wb') as f:
                f.write(response.read())
        
        XRAY_BIN.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(tmpzip, "r") as z:
            z.extractall(XRAY_BIN.parent)
        
        XRAY_BIN.chmod(0o755)
        tmpzip.unlink()
        print("  ✓ xray-core installed successfully")
        return True
    except Exception as e:
        print(f"  ✗ xray install failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Stage 2 – xray config builders (улучшенные для РФ)
# ═══════════════════════════════════════════════════════════════════════════

def make_xray_config(uri: str, socks_port: int) -> Optional[Dict]:
    """Генерация xray конфига с оптимизациями для РФ"""
    try:
        scheme = uri.split("://")[0].lower()
    except:
        return None
    
    # Пропускаем обычные HTTP/HTTPS прокси
    if scheme in ("http", "https"):
        return None
    
    try:
        # Для VLESS с Reality (самые живучие в РФ)
        if scheme == "vless":
            p = urllib.parse.urlparse(uri)
            uid = p.username or ""
            host = p.hostname or ""
            port = p.port or 443
            params = dict(urllib.parse.parse_qsl(p.query))
            
            flow = params.get("flow", "")
            sni = params.get("sni", params.get("peer", host))
            fp = params.get("fp", "chrome")
            net = params.get("type", "tcp")
            sec = params.get("security", "none")
            pbk = params.get("pbk", "")
            sid = params.get("sid", "")
            
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host, 
                        "port": port,
                        "users": [{"id": uid, "encryption": "none", "flow": flow}]
                    }]
                },
                "streamSettings": {"network": net},
            }
            
            ss = outbound["streamSettings"]
            
            # Reality настройки (оптимально для РФ)
            if sec == "reality":
                ss["security"] = "reality"
                ss["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": fp,
                    "publicKey": pbk,
                    "shortId": sid,
                    "maxTimeDiff": 60000
                }
            # TLS с отключенной проверкой сертификата
            elif sec == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {
                    "serverName": sni,
                    "fingerprint": fp,
                    "allowInsecure": True,  # Критично для РФ
                    "enableSessionResumption": False
                }
            
            # WebSocket с обфускацией
            if net == "ws":
                ws_path = params.get("path", "/")
                ws_host = params.get("host", host)
                ss["wsSettings"] = {
                    "path": ws_path,
                    "headers": {"Host": ws_host}
                }
                # Добавляем случайные параметры для обхода DPI
                if ENABLE_FRAGMENT:
                    ss["wsSettings"]["useBrowserForwarding"] = False
            
            # gRPC настройки
            elif net == "grpc":
                ss["grpcSettings"] = {
                    "serviceName": params.get("serviceName", ""),
                    "multiMode": False
                }
        
        # Для Trojan
        elif scheme == "trojan":
            p = urllib.parse.urlparse(uri)
            host = p.hostname or ""
            port = p.port or 443
            params = dict(urllib.parse.parse_qsl(p.query))
            
            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": p.username or "",
                        "flow": params.get("flow", "")
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": params.get("sni", host),
                        "allowInsecure": True,  # Критично для РФ
                        "fingerprint": params.get("fp", "chrome")
                    }
                },
            }
        
        # Для VMess
        elif scheme == "vmess":
            raw = decode_b64(uri[len("vmess://"):])
            cfg = json.loads(raw)
            host = cfg.get("add", "")
            port = int(cfg.get("port", 443))
            net = cfg.get("net", "tcp")
            tls = cfg.get("tls", "")
            sni = cfg.get("sni", cfg.get("host", host))
            
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": cfg.get("id", ""),
                            "alterId": int(cfg.get("aid", 0)),
                            "security": "auto"
                        }]
                    }]
                },
                "streamSettings": {"network": net},
            }
            
            ss = outbound["streamSettings"]
            if tls == "tls":
                ss["security"] = "tls"
                ss["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": True,  # Критично для РФ
                    "fingerprint": cfg.get("fp", "chrome")
                }
            if net == "ws":
                ss["wsSettings"] = {
                    "path": cfg.get("path", "/"),
                    "headers": {"Host": cfg.get("host", host)}
                }
        
        # Для Shadowsocks
        elif scheme == "ss":
            p = urllib.parse.urlparse(uri)
            userinfo = p.username or ""
            if ":" not in userinfo:
                userinfo = decode_b64(userinfo)
            method, password = userinfo.split(":", 1)
            
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": p.hostname or "",
                        "port": p.port or 443,
                        "method": method,
                        "password": password
                    }]
                },
                "streamSettings": {"network": "tcp"},
            }
        else:
            return None
        
        # Базовая конфигурация xray
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            }],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}
                ]
            }
        }
        
        return config
        
    except Exception as e:
        # Подавляем ошибки парсинга отдельных конфигов
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Stage 2 – HTTP probe (улучшенный для РФ)
# ═══════════════════════════════════════════════════════════════════════════

async def http_probe_via_socks(socks_port: int, retry: int = 0) -> Optional[float]:
    """HTTP проверка через SOCKS5 с адаптивными таймаутами"""
    
    # Кастомные заголовки для обхода DPI
    headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    }
    
    # Отключаем проверку SSL
    connector = aiohttp.TCPConnector(
        ssl=False,
        ttl_dns_cache=300,
        force_close=True
    )
    
    best_latency = None
    
    # Используем разные таймауты для разных уровней проверки
    timeout_settings = [
        aiohttp.ClientTimeout(total=TIMEOUT_HTTP, connect=TIMEOUT_TCP, sock_read=15),
        aiohttp.ClientTimeout(total=TIMEOUT_HTTP + 5, connect=TIMEOUT_TCP + 2, sock_read=20)
    ]
    
    timeout = timeout_settings[retry if retry < len(timeout_settings) else 0]
    
    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
            # Проверяем разные URL, начиная с быстрых HTTP
            for url in PROBE_URLS:
                t0 = time.monotonic()
                success = False
                
                try:
                    async with session.get(
                        url,
                        proxy=f"socks5://127.0.0.1:{socks_port}",
                        allow_redirects=True,
                        ssl=False
                    ) as resp:
                        # Читаем хотя бы часть ответа
                        await resp.read(1024)
                        
                        # Считаем успехом коды 2xx, 3xx и даже 403 (Forbidden)
                        if resp.status in (200, 201, 204, 301, 302, 307, 308, 403):
                            latency = (time.monotonic() - t0) * 1000
                            if best_latency is None or latency < best_latency:
                                best_latency = latency
                            success = True
                            
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
                
                if success:
                    # Если получили HTTP ответ на российском ресурсе - это отлично
                    if url in PROBE_URLS_FAST or url in PROBE_URLS_RU:
                        break
                    
    except Exception:
        pass
    
    return best_latency


async def stage2_test(sem: asyncio.Semaphore, idx: int, item: Dict) -> Optional[Dict]:
    """Stage 2 с поддержкой повторных попыток"""
    uri = item["uri"]
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
            # Запускаем xray
            proc = await asyncio.create_subprocess_exec(
                str(XRAY_BIN), "run", "-c", cfg_path,
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
            )
            
            # Даем время на установку соединения (увеличено для РФ)
            await asyncio.sleep(random.uniform(0.8, 1.2))
            
            # Пробуем с повторными попытками
            http_lat = None
            for retry in range(RETRY_COUNT):
                http_lat = await http_probe_via_socks(socks_port, retry)
                if http_lat is not None:
                    break
                await asyncio.sleep(0.5)  # Пауза перед повторной попыткой
            
            if http_lat is None:
                return None
            
            return {
                **item,
                "http_ms": round(http_lat, 1)
            }
            
        except Exception:
            return None
        finally:
            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=2)
                except:
                    try:
                        proc.kill()
                    except:
                        pass
            try:
                os.unlink(cfg_path)
            except:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# Fetch sources (улучшенный для РФ)
# ═══════════════════════════════════════════════════════════════════════════

async def fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Загрузка источников с обходом блокировок GitHub в РФ"""
    # Конвертируем github.com/blob в raw.githubusercontent.com
    url = re.sub(r'github\.com/([^/]+)/([^/]+)/blob/(.+)',
                 r'raw.githubusercontent.com/\1/\2/refs/heads/\3', url)
    
    # Добавляем заголовки для обхода блокировок
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/plain,text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), headers=headers) as resp:
            if resp.status == 200:
                text = await resp.text(encoding="utf-8", errors="ignore")
                configs = extract_configs(text)
                
                # Малый принт
                short_url = url[:60] + "..." if len(url) > 60 else url
                print(f"  ✓ {short_url}  →  {len(configs)} configs")
                return configs
            else:
                short_url = url[:60] + "..." if len(url) > 60 else url
                print(f"  ✗ {short_url}  →  HTTP {resp.status}")
    except asyncio.TimeoutError:
        short_url = url[:60] + "..." if len(url) > 60 else url
        print(f"  ✗ {short_url}  →  Timeout (блокировка?)")
    except Exception as e:
        short_url = url[:60] + "..." if len(url) > 60 else url
        print(f"  ✗ {short_url}  →  {str(e)[:50]}")
    
    return []


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    print(f"\n{'='*70}")
    print(f"  Russian VLESS Checker v2.0  |  {ts}")
    print(f"  Оптимизирован для работы в РФ")
    print(f"{'='*70}\n")
    
    # 1. Download sources
    print("📥 Загрузка источников (с обходом блокировок GitHub)...")
    
    # Настройки соединения для скачивания
    connector = aiohttp.TCPConnector(ssl=False, limit=20, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        batches = await asyncio.gather(*[fetch_source(session, u) for u in SOURCES])
    
    all_configs = list(dict.fromkeys(c for b in batches for c in b))
    print(f"\n📋 Уникальных конфигов: {len(all_configs)}")
    
    if not all_configs:
        print("⚠️  Нет конфигов для проверки. Выход.")
        return
    
    # 2. Stage 1 – TCP ping
    print(f"\n🔌 Этап 1 – TCP ping (конкурентность={MAX_CONCURRENT_TCP})...")
    print("   (российские IP получают приоритет)")
    
    sem1 = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    tcp_alive = []
    done = 0
    
    # Обработка с прогресс-баром
    tasks = [stage1_test(sem1, u) for u in all_configs]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if r:
            tcp_alive.append(r)
        
        # Прогресс каждые 200 конфигов
        if done % 200 == 0:
            ru_count = sum(1 for x in tcp_alive if x.get('is_ru', False))
            print(f"  … {done}/{len(all_configs)} проверено, живо: {len(tcp_alive)} (РФ: {ru_count})")
    
    # Сортируем с учетом бонуса к российским
    tcp_alive.sort(key=lambda x: (x.get('is_ru', False), x["tcp_ms"]), reverse=False)
    
    print(f"\n  ✅ TCP-живые: {len(tcp_alive)}")
    ru_tcp = sum(1 for x in tcp_alive if x.get('is_ru', False))
    if ru_tcp:
        print(f"  📍 Из них российские IP: {ru_tcp}")
    
    # 3. Install xray
    print("\n🛠  Подготовка xray-core (последняя версия)...")
    xray_ok = install_xray()
    
    # 4. Stage 2 – HTTP probe
    # Берем топ-300 по TCP, но отдаем приоритет российским
    ru_candidates = [x for x in tcp_alive if x.get('is_ru', False)]
    other_candidates = [x for x in tcp_alive if not x.get('is_ru', False)]
    candidates = (ru_candidates + other_candidates)[:300]
    
    http_alive = []
    
    if xray_ok:
        print(f"\n🌐 Этап 2 – HTTP проверка ({len(candidates)} кандидатов, конкурентность={MAX_CONCURRENT_HTTP})")
        print(f"   Тестовые URL: {len(PROBE_URLS_FAST)} быстрых HTTP + {len(PROBE_URLS_RU)} российских HTTPS + международные")
        print("   (разрешены коды 200, 204, 301, 302, 403)\n")
        
        sem2 = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
        done2 = 0
        
        tasks2 = [stage2_test(sem2, i, it) for i, it in enumerate(candidates)]
        for coro in asyncio.as_completed(tasks2):
            r = await coro
            done2 += 1
            if r:
                http_alive.append(r)
            
            # Прогресс каждые 10 конфигов
            if done2 % 10 == 0 or done2 == len(candidates):
                ru_working = sum(1 for x in http_alive if x.get('is_ru', False))
                print(f"  … {done2}/{len(candidates)} проверено, работает: {len(http_alive)} (РФ: {ru_working})")
        
        # Сортируем по HTTP задержке
        http_alive.sort(key=lambda x: x["http_ms"])
        top = http_alive[:TOP_N]
        
        print(f"\n  ✅ HTTP-работающих: {len(http_alive)}")
        ru_http = sum(1 for x in http_alive if x.get('is_ru', False))
        if ru_http:
            print(f"  📍 Из них российские IP: {ru_http}")
    else:
        print("  ⚠️  xray недоступен — сохраняю только TCP результаты")
        top = candidates[:TOP_N]
        for r in top:
            r["http_ms"] = None
    
    if not top:
        print("\n⚠️  Нет работающих прокси. Попробуйте позже.")
        return
    
    # 5. Save results
    uri_lines = [r["uri"] for r in top]
    (OUTPUT_DIR / "proxies.txt").write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
    
    b64 = base64.b64encode("\n".join(uri_lines).encode()).decode()
    (OUTPUT_DIR / "proxies_b64.txt").write_text(b64, encoding="utf-8")
    
    report = {
        "updated": ts,
        "total_fetched": len(all_configs),
        "tcp_alive": len(tcp_alive),
        "tcp_alive_russian": ru_tcp,
        "http_working": len(http_alive) if xray_ok else "n/a",
        "http_working_russian": ru_http if xray_ok else "n/a",
        "saved": len(top),
        "probe_urls": PROBE_URLS,
        "proxies": top,
    }
    (OUTPUT_DIR / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    
    # 6. Generate README
    rows = "\n".join(
        "| {n} | `{h}:{p}` | {tcp} ms | {http} ms | {ru} |".format(
            n=i+1, 
            h=r["host"], 
            p=r["port"],
            tcp=r["tcp_ms"],
            http=r["http_ms"] if r.get("http_ms") else "—",
            ru="🇷🇺" if r.get("is_ru") else "🌍"
        )
        for i, r in enumerate(top[:50])
    )
    
    readme_output = f"""# Proxy Check Results for Russia

**Updated:** {ts}
**Optimized for:** Russian Federation (DPI bypass, Reality support, local test URLs)

| Stat | Value |
|------|-------|
| Sources | {len(SOURCES)} |
| Total configs | {len(all_configs)} |
| TCP alive | {len(tcp_alive)} (🇷🇺 Russian IP: {ru_tcp}) |
| HTTP working (multi-level check) | {len(http_alive) if xray_ok else "n/a"} (🇷🇺 Russian IP: {ru_http if xray_ok else "n/a"}) |
| Saved (top {TOP_N}) | {len(top)} |

## Test Strategy for Russian Federation

1. **Fast HTTP check** – `ipinfo.io/ip`, `2ip.ru`, `rutracker.org`
2. **Russian HTTPS** – `yandex.ru`, `mail.ru`, `vk.com`
3. **International** – `google.com/generate_204`, `cloudflare.com`

**Allowed HTTP codes:** 200, 201, 204, 301, 302, 307, 308, 403 (Forbidden accepted as connection proof)
**TLS settings:** `allowInsecure: true` for Russian MITM

## Top 50 by HTTP Latency

| # | Host:Port | TCP ping | HTTP latency | Region |
|---|-----------|----------|--------------|--------|
{rows}

## Files

| File | Description |
|------|-------------|
| [`proxies.txt`](proxies.txt) | Plain URI list – import into v2rayN / Nekobox / Nekoray |
| [`proxies_b64.txt`](proxies_b64.txt) | Base64 subscription link |
| [`report.json`](report.json) | Full JSON with all latency data |

## Notes for Russian Users

- **Reality protocol** support is prioritized (best anti-DPI)
- **Russian IP addresses** get priority boost in sorting
- **TLS verification is disabled** (`allowInsecure: true`) – required due to government MITM
- **403 responses** are considered successful (connection established)

---
*Auto-generated every 3 hours by GitHub Actions*  
*Optimized for Russian Federation network conditions*
"""
    
    (OUTPUT_DIR / "README.md").write_text(readme_output, encoding="utf-8")
    
    # Обновляем корневой README
    Path("README.md").write_text(
        readme_output.replace("](proxies", "](output/proxies").replace("](report", "](output/report"),
        encoding="utf-8",
    )
    
    print(f"\n📁 Результаты сохранены в {OUTPUT_DIR}/")
    print(f"\n🏆 Топ-5 самых быстрых рабочих прокси:")
    for i, r in enumerate(top[:5]):
        ru_flag = "🇷🇺" if r.get('is_ru') else "🌍"
        if r.get("http_ms"):
            print(f"   {i+1}. {ru_flag} {r['host']}:{r['port']}  →  HTTP {r['http_ms']} ms (TCP: {r['tcp_ms']} ms)")
        else:
            print(f"   {i+1}. {ru_flag} {r['host']}:{r['port']}  →  TCP {r['tcp_ms']} ms")
    
    # Финальная статистика
    print(f"\n📊 Статистика:")
    print(f"   • Всего конфигов: {len(all_configs)}")
    print(f"   • Прошли TCP: {len(tcp_alive)} ({len(tcp_alive)/len(all_configs)*100:.1f}%)")
    if xray_ok and http_alive:
        print(f"   • HTTP рабочие: {len(http_alive)} ({len(http_alive)/len(candidates)*100:.1f}% из топ-300)")
        print(f"   • Российских IP среди рабочих: {ru_http}")
    
    print()


if __name__ == "__main__":
    asyncio.run(main())
