import ipaddress
import json
import os
import urllib.request
from pathlib import Path

CACHE_FILE = Path("data/ip_cache.json")
DEMO_GEO_FILE = Path("data/demo_geo.json")
GEO_FIELDS = "status,country,regionName,city,isp,as,timezone,hosting,proxy"


def load_cache():
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {}


def save_cache(cache):
    CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False))


def fetch_json(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            return json.loads(response.read().decode())
    except Exception:
        return None


def lookup_geo(ip):
    data = fetch_json(f"http://ip-api.com/json/{ip}?fields={GEO_FIELDS}")
    if data and data.get("status") == "success":
        data.pop("status")
        return data
    return {}


def lookup_abuse(ip):
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    data = fetch_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
        {"Key": key, "Accept": "application/json"},
    )
    if data:
        return data["data"]["abuseConfidenceScore"]
    return None


def demo_info(ip):
    if os.environ.get("LAB_DEMO_GEO") != "1" or not DEMO_GEO_FILE.exists():
        return None
    try:
        if ipaddress.ip_address(ip).is_global:
            return None
    except ValueError:
        return None
    entry = json.loads(DEMO_GEO_FILE.read_text(encoding="utf-8")).get(ip)
    if not entry:
        return None
    info = {"scope": "simulado", "simulated": True, **entry}
    info["country"] = f"{entry.get('country', '?')} (simulado)"
    return info


def enrich_ip(ip, cache):
    demo = demo_info(ip)
    if demo:
        return demo
    if ip in cache:
        return cache[ip]
    try:
        is_public = ipaddress.ip_address(ip).is_global
    except ValueError:
        return {"scope": "invalido"}
    if not is_public:
        cache[ip] = {"scope": "privado/reservado"}
        return cache[ip]
    info = {"scope": "publico", **lookup_geo(ip)}
    score = lookup_abuse(ip)
    if score is not None:
        info["abuse_score"] = score
    if "country" in info:
        cache[ip] = info
    return info
