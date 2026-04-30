#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import base64
import urllib.parse
import time
import subprocess
import os
import tempfile

XRAY_BIN = "xray"
SOCKS_PORT = 10808

PROBE_URLS = [
    "http://www.google.com/generate_204",
    "https://cp.cloudflare.com/",
    "https://telegram.org/"
]

CONCURRENCY = 20


# ─────────────────────────────
# PARSE VLESS
# ─────────────────────────────
def parse_vless(uri: str):
    p = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(p.query))

    return {
        "uri": uri,
        "host": p.hostname,
        "port": p.port or 443,
        "uuid": p.username,
        "params": params
    }


# ─────────────────────────────
# TCP PING (metric only)
# ─────────────────────────────
async def tcp_ping(host: str, port: int, timeout=2.5):
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return (time.time() - start) * 1000
    except:
        return None


# ─────────────────────────────
# BUILD XRAY CONFIG
# ─────────────────────────────
def build_config(node):
    p = node["params"]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": node["host"],
                "port": node["port"],
                "users": [{
                    "id": node["uuid"],
                    "encryption": "none"
                }]
            }]
        },
        "streamSettings": {
            "network": p.get("type", "tcp"),
            "security": p.get("security", "none")
        }
    }

    ss = outbound["streamSettings"]

    if p.get("security") == "tls":
        ss["tlsSettings"] = {
            "serverName": p.get("sni", node["host"])
        }

    if p.get("security") == "reality":
        ss["realitySettings"] = {
            "serverName": p.get("sni", node["host"]),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", "")
        }

    if p.get("type") == "ws":
        ss["wsSettings"] = {
            "path": p.get("path", "/"),
            "headers": {"Host": p.get("host", node["host"])}
        }

    return {
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {"auth": "noauth"}
        }],
        "outbounds": [outbound]
    }


# ─────────────────────────────
# HTTP PROBE
# ─────────────────────────────
async def probe():
    start = time.time()
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url in PROBE_URLS:
                try:
                    async with session.get(
                        url,
                        proxy=f"socks5://127.0.0.1:{SOCKS_PORT}"
                    ) as r:
                        await r.read()
                        if r.status in (200, 204):
                            return (time.time() - start) * 1000
                except:
                    continue
    except:
        pass
    return None


# ─────────────────────────────
# CHECK NODE
# ─────────────────────────────
async def check_node(uri):
    node = parse_vless(uri)

    tcp_task = asyncio.create_task(
        tcp_ping(node["host"], node["port"])
    )

    cfg = build_config(node)

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f)
        path = f.name

    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-c", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    await asyncio.sleep(1.0)

    http_lat = await probe()
    tcp_lat = await tcp_task

    proc.kill()
    os.remove(path)

    return {
        "uri": uri,
        "tcp_ms": tcp_lat,
        "http_ms": http_lat,
        "ok": http_lat is not None
    }


# ─────────────────────────────
# SCORE
# ─────────────────────────────
def score(x):
    tcp = x["tcp_ms"] or 9999
    http = x["http_ms"] or 9999
    return http * 0.8 + tcp * 0.2


# ─────────────────────────────
# RUNNER
# ─────────────────────────────
async def run(nodes):
    sem = asyncio.Semaphore(CONCURRENCY)

    async def worker(n):
        async with sem:
            return await check_node(n)

    results = await asyncio.gather(*[worker(n) for n in nodes])

    return sorted(
        [r for r in results if r["ok"]],
        key=score
    )
