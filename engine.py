import glob
from collections import defaultdict, deque
from datetime import datetime, timedelta

import yaml

from enrichment import enrich_ip, load_cache, save_cache
from event_model import load_events


def load_rules(folder):
    rules = []
    for path in sorted(glob.glob(f"{folder}/*.yml")):
        with open(path) as f:
            rules.append(yaml.safe_load(f))
    return rules


def get_field(event, key):
    value = event
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def matches(rule, event):
    for key, expected in rule["match"].items():
        if get_field(event, key) != expected:
            return False
    return True


def parse_time(event):
    return datetime.fromisoformat(event["timestamp"])


def make_alert(rule, src_ip, timestamp, count, related=None):
    return {
        "rule_id": rule["id"],
        "name": rule["name"],
        "severity": rule["severity"],
        "src_ip": src_ip,
        "timestamp": timestamp,
        "count": count,
        "mitre": rule.get("mitre", []),
        "related": related or [],
    }


def detect(rules, events):
    alerts = []
    windows = defaultdict(deque)
    for event in sorted(events, key=parse_time):
        now = parse_time(event)
        for rule in rules:
            if not matches(rule, event):
                continue
            threshold = rule.get("threshold")
            if not threshold:
                alerts.append(make_alert(rule, event["src_ip"], event["timestamp"], 1))
                continue
            group = get_field(event, threshold["group_by"])
            window = windows[(rule["id"], group)]
            window.append(now)
            limit = now - timedelta(seconds=threshold["window_seconds"])
            while window and window[0] < limit:
                window.popleft()
            if len(window) >= threshold["count"]:
                alerts.append(make_alert(rule, event["src_ip"], event["timestamp"], len(window)))
                window.clear()
    return alerts


def correlate(rules, alerts):
    results = []
    for rule in rules:
        corr = rule["correlation"]
        window = timedelta(seconds=corr["window_seconds"])
        latest = defaultdict(dict)
        for alert in alerts:
            if alert["rule_id"] in corr["requires"]:
                group = alert[corr["group_by"]]
                latest[group][alert["rule_id"]] = alert
        for group, found in latest.items():
            if set(found) != set(corr["requires"]):
                continue
            times = [datetime.fromisoformat(a["timestamp"]) for a in found.values()]
            if max(times) - min(times) <= window:
                last = max(found.values(), key=lambda a: a["timestamp"])
                results.append(make_alert(rule, group, last["timestamp"], len(found), list(found)))
    return results


def evaluate(rules, events):
    base = [r for r in rules if "match" in r]
    corr = [r for r in rules if "correlation" in r]
    alerts = detect(base, events)
    return alerts + correlate(corr, alerts)


def main():
    rules = load_rules("rules")
    events = load_events("data/sample.jsonl")
    alerts = evaluate(rules, events)

    cache = load_cache()
    for a in alerts:
        a["enrichment"] = enrich_ip(a["src_ip"], cache)
    save_cache(cache)

    for a in alerts:
        techniques = ", ".join(m["id"] for m in a["mitre"]) or "-"
        info = a["enrichment"]
        where = info.get("country", info.get("scope", "?"))
        print(f"[{a['severity'].upper()}] {a['rule_id']} - {a['name']} | ip={a['src_ip']} ({where}) | ATT&CK: {techniques}")


if __name__ == "__main__":
    main()
