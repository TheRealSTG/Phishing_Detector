"""
threat_feeds.py
---------------
Downloads and caches known-malicious URL feeds from:
  - OpenPhish  (https://openphish.com/feed.txt)
  - URLhaus    (https://urlhaus.abuse.ch/downloads/text/)

Both are free, no API key required.

The feeds are stored as a set of registered domains (e.g. 'evil.com') so
lookups are O(1) and subdomains still match.

Feeds are refreshed every REFRESH_HOURS hours automatically.
"""

import os
import time
import threading

import requests
import tldextract

# Config
OPENPHISH_URL  = "https://openphish.com/feed.txt"
URLHAUS_URL    = "https://urlhaus.abuse.ch/downloads/text/"
CACHE_FILE     = "threat_feed_cache.txt"
REFRESH_HOURS  = 6
FETCH_TIMEOUT  = 20     # seconds per request

# In-memory store
_feed_domains: set[str] = set()
_last_updated: float    = 0.0
_lock                   = threading.Lock()


def _extract_domain(url: str) -> str | None:
    """Returns the registered domain (e.g. 'evil.com') from a URL, or None."""
    try:
        ext = tldextract.extract(url.strip())
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return None


def _fetch_feed(url: str) -> list[str]:
    """Downloads a newline-delimited URL feed. Returns list of raw URLs."""
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        # Skip comment lines (start with #)
        return [line.strip() for line in lines if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[threat_feeds] Failed to fetch {url}: {e}")
        return []


def refresh_feeds(force: bool = False) -> None:
    """
    Downloads both feeds and rebuilds the in-memory domain set.
    Skips if the feeds were updated within REFRESH_HOURS unless force=True.
    """
    global _last_updated

    age_hours = (time.time() - _last_updated) / 3600
    if not force and age_hours < REFRESH_HOURS:
        return

    print(f"[threat_feeds] Refreshing feeds (last update {age_hours:.1f}h ago)...")

    domains: set[str] = set()

    for feed_url in (OPENPHISH_URL, URLHAUS_URL):
        raw_urls = _fetch_feed(feed_url)
        for raw in raw_urls:
            domain = _extract_domain(raw)
            if domain:
                domains.add(domain)

    # Also persist to disk so restarts are fast
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(domains)))
    except Exception as e:
        print(f"[threat_feeds] Could not write cache file: {e}")

    with _lock:
        _feed_domains.clear()
        _feed_domains.update(domains)
        _last_updated = time.time()

    print(f"[threat_feeds] Loaded {len(_feed_domains):,} malicious domains into feed.")


def load_from_cache() -> None:
    """
    Loads the on-disk cache at startup for a fast boot.
    Falls back to an empty set if the file doesn't exist yet.
    """
    global _last_updated

    if not os.path.exists(CACHE_FILE):
        print("[threat_feeds] No cache file found — will download on first check.")
        return

    cache_age_hours = (time.time() - os.path.getmtime(CACHE_FILE)) / 3600

    with open(CACHE_FILE, 'r', encoding='utf-8') as f:
        domains = {line.strip() for line in f if line.strip()}

    with _lock:
        _feed_domains.update(domains)
        _last_updated = time.time() - (cache_age_hours * 3600)

    print(f"[threat_feeds] Loaded {len(_feed_domains):,} domains from cache "
          f"(cache is {cache_age_hours:.1f}h old).")

    # If cache is stale, refresh in a background thread so boot isn't blocked
    if cache_age_hours >= REFRESH_HOURS:
        print("[threat_feeds] Cache is stale — refreshing in background...")
        threading.Thread(target=refresh_feeds, daemon=True).start()


def is_known_malicious(url: str) -> bool:
    """
    Returns True if the URL's registered domain appears in any threat feed.

    Automatically triggers a background refresh if feeds are stale
    so the in-memory set is always reasonably up to date.
    """
    # Trigger background refresh if stale (non-blocking)
    if (time.time() - _last_updated) / 3600 >= REFRESH_HOURS:
        threading.Thread(target=refresh_feeds, daemon=True).start()

    domain = _extract_domain(url)
    if not domain:
        return False

    with _lock:
        return domain in _feed_domains
