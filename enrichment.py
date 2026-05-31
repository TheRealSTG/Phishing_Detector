"""
enrichment.py
-------------
Runtime enrichment signals that are too slow to run at training time
(WHOIS lookups, etc.) but are valuable at scan time.

Results are cached in-memory for CACHE_TTL_SECONDS to avoid hammering
WHOIS servers when the same domain is scanned repeatedly.
"""

import time
import threading
from datetime import datetime

import tldextract

# Lazy import so startup isn't slow if whois isn't installed
try:
    import whois as _whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("[enrichment] python-whois not installed. Domain age checks disabled.")


# Simple TTL cache
_cache: dict[str, tuple[dict, float]] = {}   # domain → (result, expiry_ts)
_cache_lock  = threading.Lock()
CACHE_TTL    = 3600 * 24   # 24 hours — WHOIS data doesn't change that fast


def _get_cached(domain: str) -> dict | None:
    with _cache_lock:
        entry = _cache.get(domain)
        if entry and time.time() < entry[1]:
            return entry[0]
    return None


def _set_cached(domain: str, data: dict) -> None:
    with _cache_lock:
        _cache[domain] = (data, time.time() + CACHE_TTL)

    # Evict if cache grows too large
    with _cache_lock:
        if len(_cache) > 5000:
            oldest = sorted(_cache.items(), key=lambda x: x[1][1])[:1000]
            for k, _ in oldest:
                del _cache[k]


# WHOIS domain age

def get_domain_age_days(url: str) -> int | None:
    """
    Returns the age of the domain in days, or None if lookup fails.

    Cached for 24h per domain. Falls back to None on timeout or error.

    Why this matters:
        Phishing domains are almost always < 30 days old.
        Registering a new domain costs ~$1 and takes minutes.
        Legitimate sites are typically years old.
    """
    if not WHOIS_AVAILABLE:
        return None

    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        if not domain:
            return None
    except Exception:
        return None

    # Check cache first
    cached = _get_cached(domain)
    if cached is not None:
        return cached.get('age_days')

    try:
        w = _whois.whois(domain)
        creation = w.creation_date

        # creation_date can be a list (some registrars return multiple dates)
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            _set_cached(domain, {'age_days': None})
            return None

        # Normalise to naive datetime
        if hasattr(creation, 'replace'):
            creation = creation.replace(tzinfo=None)

        age_days = (datetime.utcnow() - creation).days
        _set_cached(domain, {'age_days': age_days})
        return age_days

    except Exception as e:
        # WHOIS can fail for many reasons (no record, timeout, rate limit)
        _set_cached(domain, {'age_days': None})
        return None


def build_enrichment_flags(url: str) -> list[str]:
    """
    Returns a list of human-readable enrichment-based risk flags.
    These are displayed alongside the ML model's SHAP explanation.

    Each flag represents a signal that doesn't come from the model itself
    but from live data lookups.
    """
    flags: list[str] = []

    age = get_domain_age_days(url)
    if age is not None:
        if age < 30:
            flags.append(f"Domain is only {age} day{'s' if age != 1 else ''} old — very new domains are high risk")
        elif age < 180:
            flags.append(f"Domain is {age} days old — relatively new")

    return flags
