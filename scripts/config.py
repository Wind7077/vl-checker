# scripts/config.py
"""
Configuration for proxy checker.
Settings can be overridden via environment variables.
"""

import os
from typing import Dict, List, Set

# ============================================================================
#  LOAD CONFIGURATION FROM ENVIRONMENT VARIABLES
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

# ── Geo filter (ISO country codes, e.g., "NL,DE,US") ──────────────────────
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

# Protocol bonus (negative = preferred; smaller score is better)
PROTO_BONUS: Dict[str, int] = {
    "hysteria2": 100,
    "vless": 0,
    "trojan": 0,
    "ss": 0,
    "vmess": 0,
}

# ── Probe URLs (URL, allowed HTTP status codes) ───────────────────────────
PROBE_URLS = [
    ("https://cp.cloudflare.com/", {200}),
    ("https://ip.sb/", {200}),
    ("https://ifconfig.me/ip", {200}),
]
