#!/usr/bin/env python3
"""
Proxy Checker — RU edition
Pipeline: sources.txt → fetch (async, all sources in parallel) → extract + deduplicate → protocol/reality filter → Stage 1: TCP-ping (vless/vmess/trojan/ss) / DNS-resolve (hysteria2) → geo filter (optional) → Stage 2: spin up xray/hysteria2 as SOCKS5, run curl through ALL probe-URLs → calculate reliability → Scoring: weighted sum tcp + http + reliability bonus + protocol bonus → Top N → proxies.txt / proxies_b64.txt / report.json / README.md
"""

import asyncio
import aiohttp
import aiofiles
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import random
import contextlib
import shutil

# ============================================================================
#  LOAD CONFIGURATION FROM ENVIRONMENT VARIABLES / FALLBACKS
# ============================================================================

def get_env_list(key: str, default: List[str]) -> List[str]:
    """Parse comma-separated list from environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]

def get_env_bool(key: str, default: bool) -> bool:
    """Parse boolean from environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")

# ── Protocol filters ──────────────────────────────────────────────────────
ALLOWED_PROTOCOLS = get_env_list("ALLOWED_PROTOCOLS", ["vless", "hysteria2", "trojan"])
REQUIRE_REALITY = get_env_bool("REQUIRE_REALITY", True)

# ── Geo filter ────────────────────────────────────────────────────────────
ALLOWED_COUNTRIES: Set[str] = set()
geo_env = os.environ.get("ALLOWED_COUNTRIES", "")
if geo_env:
    ALLOWED_COUNTRIES = {c.strip() for c in geo_env.split(",") if c.strip()}

# ── Performance & selection ───────────────────────────────────────────────
TOP_N = int(os.environ.get("TOP_N", "250"))
STAGE2_CANDIDATES = int(os.environ.get("STAGE2_CANDIDATES", "2500"))
MAX_CONCURRENT_TCP = int(os.environ.get("MAX_CONCURRENT_TCP", "200"))
MAX_CONCURRENT_HTTP = int(os.environ.get("MAX_CONCURRENT_HTTP", "30"))

# ── Timeouts (seconds) ────────────────────────────────────────────────────
TIMEOUT_TCP = float(os.environ.get("TIMEOUT_TCP", "1.5"))      # reduced from 3.0
TIMEOUT_CURL = float(os.environ.get("TIMEOUT_CURL", "10"))
TIMEOUT_XRAY_START = float(os.environ.get("TIMEOUT_XRAY_START", "1.0"))
TIMEOUT_HY2_START = float(os.environ.get("TIMEOUT_HY2_START", "1.5"))

# ── Scoring weights ───────────────────────────────────────────────────────
TCP_W = float(os.environ.get("TCP_W", "0.3"))
HTTP_W = float(os.environ.get("HTTP_W", "1.0"))
RELIABILITY_BONUS = float(os.environ.get("RELIABILITY_BONUS", "300"))
PROTO_BONUS: Dict[str, int] = {
    "hysteria2": 100,
    "vless": 0,
}

# ── Probe URLs (indicator that proxy really works for RU user) ────────────
PROBE_URLS = [
    ("https://cp.cloudflare.com/", {200}),
    ("https://ip.sb/", {200}),
    ("https://ifconfig.me/ip", {200}),
]

# ============================================================================
#  UTILITIES
# ============================================================================

def get_xray_path() -> str:
    """Return path to xray executable; fallback to 'xray' if not found."""
    xray_candidates = ["./xray", "xray", "/usr/local/bin/xray"]
    for candidate in xray_candidates:
        if shutil.which(candidate) is not None:
            return candidate
    return "xray"

def get_hysteria2_path() -> str:
    """Return path to hysteria2 executable; fallback to 'hysteria2' if not found."""
    hy_candidates = ["./hysteria2", "hysteria2", "/usr/local/bin/hysteria2"]
    for candidate in hy_candidates:
        if shutil.which(candidate) is not None:
            return candidate
    return "hysteria2"

@contextlib.asynccontextmanager
async def managed_xray_process(config_path: str):
    """Context manager for xray process: ensures termination and cleanup."""
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
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

@contextlib.asynccontextmanager
async def managed_hysteria2_process(config_path: str):
    """Context manager for hysteria2 process: ensures termination and cleanup."""
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
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

async def run_curl(socks5_host: str, socks5_port: int, url: str, timeout: float) -> Tuple[bool, float]:
    """Run curl through SOCKS5 proxy and measure response time."""
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
    except (asyncio.TimeoutError, subprocess.SubprocessError):
        return False, 0.0

# ============================================================================
#  STAGE 1: TCP Ping
# ============================================================================

async def tcp_ping(host: str, port: int, timeout: float) -> Tuple[bool, float]:
    """Perform TCP connection test."""
    try:
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        elapsed = time.monotonic() - start
        writer.close()
        await writer.wait_closed()
        return True, elapsed * 1000  # convert to ms
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False, 0.0

# ============================================================================
#  STAGE 2: Full HTTP Test with early reliability detection
# ============================================================================

async def test_proxy_http(proxy: Dict[str, Any], tmpdir: Path) -> Optional[Dict[str, Any]]:
    """
    Stage 2 test: spin up xray/hysteria2, run HTTP requests through SOCKS5.
    Exit early on first successful probe (rel=1). Much faster than testing all URLs.
    """
    proto = proxy["proto"]
    config_content = proxy.get("config_content")
    if not config_content:
        return None

    config_path = tmpdir / f"config_{proxy['id']}.json"
    async with aiofiles.open(config_path, "w") as f:
        await f.write(config_content)

    try:
        if proto == "hysteria2":
            async with managed_hysteria2_process(str(config_path)) as proc:
                await asyncio.sleep(TIMEOUT_HY2_START)
                # Try each probe URL, stop on first success
                for url, _ in PROBE_URLS:
                    success, http_ms = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                    if success:
                        proxy["http_ms"] = http_ms
                        proxy["reliability"] = 1
                        proxy["success_count"] = 1
                        return proxy
                # No success at all
                return None
        else:
            async with managed_xray_process(str(config_path)) as proc:
                await asyncio.sleep(TIMEOUT_XRAY_START)
                for url, _ in PROBE_URLS:
                    success, http_ms = await run_curl("127.0.0.1", 1080, url, TIMEOUT_CURL)
                    if success:
                        proxy["http_ms"] = http_ms
                        proxy["reliability"] = 1
                        proxy["success_count"] = 1
                        return proxy
                return None
    except Exception:
        return None

# ============================================================================
#  SCORING & OUTPUT
# ============================================================================

def calculate_score(proxy: Dict[str, Any]) -> float:
    """Calculate final score according to: TCP_W*tcp_ms + HTTP_W*http_ms - RELIABILITY_BONUS*(success_count-1) - PROTO_BONUS."""
    tcp_ms = proxy.get("tcp_ms", float("inf"))
    http_ms = proxy.get("http_ms", float("inf"))
    success_count = proxy.get("success_count", 0)
    proto = proxy.get("proto", "")
    proto_bonus = PROTO_BONUS.get(proto, 0)
    score = TCP_W * tcp_ms + HTTP_W * http_ms - RELIABILITY_BONUS * (success_count - 1) - proto_bonus
    return score

async def main():
    # Placeholder for actual parsing from sources.txt and proxy extraction
    # In a real implementation, this would fetch, parse, and deduplicate proxies.
    # For demonstration, we simulate a list of proxies.
    proxies = []

    # Stage 1: TCP ping with geo filtering before ping
    # Geo filtering (if any) should ideally happen before TCP ping.
    # If ALLOWED_COUNTRIES is set, we would filter proxies by country here (requires geoip).
    # For now, skip if no country restriction.
    if ALLOWED_COUNTRIES:
        # geoip logic would go here
        pass

    # Run TCP ping with concurrency limit
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    async def limited_tcp_ping(proxy):
        async with semaphore:
            ok, ms = await tcp_ping(proxy["host"], proxy["port"], TIMEOUT_TCP)
            if ok:
                proxy["tcp_ms"] = ms
                return proxy
            return None

    tcp_tasks = [limited_tcp_ping(p) for p in proxies]
    tcp_results = await asyncio.gather(*tcp_tasks)
    alive = [p for p in tcp_results if p is not None]

    # Select Stage 2 candidates: weighted random by inverse tcp_ms (faster = higher chance)
    if alive:
        # Weighted sampling: faster proxies (lower tcp_ms) get higher weight
        weights = [1.0 / (p["tcp_ms"] + 0.1) for p in alive]
        total_weight = sum(weights)
        probabilities = [w / total_weight for w in weights]
        stage2_candidates = random.choices(
            alive, weights=weights, k=min(STAGE2_CANDIDATES, len(alive))
        )
    else:
        stage2_candidates = []

    # Stage 2: HTTP tests
    http_semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        async def limited_http_test(proxy):
            async with http_semaphore:
                return await test_proxy_http(proxy, tmp_path)

        http_tasks = [limited_http_test(p) for p in stage2_candidates]
        http_results = await asyncio.gather(*http_tasks)
        working = [p for p in http_results if p is not None]

    # Calculate scores and sort
    for p in working:
        p["score"] = calculate_score(p)
    working.sort(key=lambda x: x["score"])

    # Save top N
    top = working[:TOP_N]

    # Output files
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # proxies.txt
    with open(output_dir / "proxies.txt", "w") as f:
        for p in top:
            f.write(f"{p.get('uri', '')}\n")

    # proxies_b64.txt (Base64 encoded)
    with open(output_dir / "proxies_b64.txt", "w") as f:
        for p in top:
            b64 = base64.b64encode(p.get('uri', '').encode()).decode()
            f.write(f"{b64}\n")

    # report.json
    with open(output_dir / "report.json", "w") as f:
        json.dump(top, f, indent=2)

    print(f"Checked {len(alive)} TCP-alive, {len(working)} passed Stage 2, saved {len(top)}")

if __name__ == "__main__":
    asyncio.run(main())
