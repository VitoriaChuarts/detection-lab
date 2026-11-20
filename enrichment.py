import ipaddress
import json
import os
import urllib.request
from pathlib import Path

CACHE_FILE = Path("data/ip_cache.json")


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
    data = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp")
    if data and data.get("status") == "success":
        return {"country": data["country"], "city": data["city"], "isp": data["isp"]}
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


def enrich_ip(ip, cache):
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
