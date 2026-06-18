"""
Fetches and caches data from the PAN-OS XML API.
Cache lives in .panos_cache.json — gitignored, refreshed automatically when stale.
"""
import json
import os
import time
import requests
import urllib3
import xml.etree.ElementTree as ET
from pathlib import Path

urllib3.disable_warnings()

CACHE_FILE = Path(".panos_cache.json")
CACHE_TTL_SECONDS = 86400       # 24 hours — for App-ID list (rarely changes)
HIT_COUNT_TTL_SECONDS = 30      # 30 seconds — operational counters, refresh frequently


def _require_env(name):
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def _get_api_key():
    hostname = _require_env("PANOS_HOSTNAME")
    username = _require_env("PANOS_USERNAME")
    password = _require_env("PANOS_PASSWORD")
    r = requests.get(
        f"https://{hostname}/api/",
        params={"type": "keygen", "user": username, "password": password},
        verify=False, timeout=15
    )
    r.raise_for_status()
    root = ET.fromstring(r.text)
    key = root.findtext(".//key")
    if not key:
        raise RuntimeError(f"Failed to get API key: {r.text[:200]}")
    return hostname, key


def _fetch_appids(hostname, key):
    r = requests.get(
        f"https://{hostname}/api/",
        params={
            "type": "config",
            "action": "get",
            "xpath": "/config/predefined/application",
            "key": key,
        },
        verify=False, timeout=30
    )
    r.raise_for_status()
    root = ET.fromstring(r.text)
    apps = sorted(e.get("name") for e in root.findall(".//application/entry") if e.get("name"))
    return apps


def _fetch_hit_counts(hostname, key):
    """
    Returns dict of {rule_name: hit_count} or empty dict if unsupported.
    Tries multiple endpoints since support varies by PAN-OS version and license.
    """
    def fetch_rulebase_hits(rulebase):
        cmd = (
            f"<show><rule-hit-count><vsys><vsys-name>"
            f"<entry name='vsys1'><rule-base><entry name='{rulebase}'>"
            f"<rules><all/></rules></entry></rule-base></entry>"
            f"</vsys-name></vsys></rule-hit-count></show>"
        )
        try:
            r = requests.get(
                f"https://{hostname}/api/",
                params={"type": "op", "cmd": cmd, "key": key},
                verify=False, timeout=15
            )
            root = ET.fromstring(r.text)
            if root.get("status") != "success":
                print(f"Hit count query ({rulebase}) non-success: {r.text[:100]}", flush=True)
                return {}
            hits = {}
            for entry in root.findall(".//rules/entry"):
                name = entry.get("name")
                count = entry.findtext("hit-count")
                last_hit = entry.findtext("last-hit-timestamp")
                if name and count is not None:
                    hits[name] = {
                        "hit_count": int(count),
                        "last_hit_timestamp": int(last_hit) if last_hit else 0,
                    }
            return hits
        except Exception as e:
            print(f"Hit count fetch ({rulebase}) failed: {e}", flush=True)
            return {}

    security_hits = fetch_rulebase_hits("security")
    nat_hits = fetch_rulebase_hits("nat")
    return {**security_hits, **nat_hits}


def load_cache():
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            age = time.time() - data.get("fetched_at", 0)
            if age < CACHE_TTL_SECONDS:
                return data
        except Exception:
            pass
    return None


def refresh_cache(force=False):
    if not force:
        cached = load_cache()
        if cached:
            return cached
    print("Refreshing PAN-OS cache (App-IDs + hit counts)...", flush=True)
    hostname, key = _get_api_key()
    appids = _fetch_appids(hostname, key)
    hit_counts = _fetch_hit_counts(hostname, key)
    data = {
        "fetched_at": time.time(),
        "appids": appids,
        "hit_counts": hit_counts,
        "hit_counts_supported": bool(hit_counts),
    }
    CACHE_FILE.write_text(json.dumps(data, indent=2))
    print(f"Cache refreshed: {len(appids)} App-IDs, "
          f"hit counts {'available' if hit_counts else 'not supported on this platform'}.",
          flush=True)
    return data


def get_appids():
    return refresh_cache().get("appids", [])


def get_hit_counts(force=False):
    """Always fetches fresh hit counts unless the data is less than 30 seconds old."""
    cached = load_cache()
    if not force and cached:
        age = time.time() - cached.get("hits_fetched_at", 0)
        if age < HIT_COUNT_TTL_SECONDS:
            return cached.get("hit_counts", {})
    try:
        hostname, key = _get_api_key()
        hits = _fetch_hit_counts(hostname, key)
        if cached:
            cached["hit_counts"] = hits
            cached["hit_counts_supported"] = bool(hits)
            cached["hits_fetched_at"] = time.time()
            CACHE_FILE.write_text(json.dumps(cached, indent=2))
        return hits
    except Exception as e:
        print(f"Hit count refresh failed: {e}", flush=True)
        return cached.get("hit_counts", {}) if cached else {}


def validate_applications(apps: list[str]) -> list[str]:
    """
    Returns list of invalid App-ID names. Empty list = all valid.
    'any' is always valid. Custom app objects are not in the predefined list
    but are flagged as unknown rather than hard-blocked.
    """
    known = set(get_appids())
    always_valid = {"any"}
    return [a for a in apps if a not in known and a not in always_valid]


if __name__ == "__main__":
    refresh_cache(force=True)
