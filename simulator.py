import json
from datetime import datetime, timedelta, timezone

from engine import evaluate, load_rules

BASE = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
USERS = ["root", "admin", "pi", "ubuntu", "test", "oracle", "user"]


def event(offset, source, event_type, ip, **details):
    return {
        "timestamp": (BASE + timedelta(seconds=offset)).isoformat(),
        "source": source,
        "event_type": event_type,
        "src_ip": ip,
        "details": details,
    }


def ssh_failures(ip, count, spacing):
    return [
        event(i * spacing, "honeypot", "ssh_login_failed", ip, username=USERS[i % len(USERS)])
        for i in range(count)
    ]


def port_scan(ip, offset):
    return [event(offset, "nids", "port_scan", ip, ports=150)]


SCENARIOS = [
    {
        "name": "Força bruta SSH",
        "technique": "T1110",
        "events": ssh_failures("198.51.100.10", 6, 5),
        "expect": {"R001", "R003"},
    },
    {
        "name": "Port scan",
        "technique": "T1046",
        "events": port_scan("198.51.100.20", 0),
        "expect": {"R002"},
    },
    {
        "name": "Ataque coordenado",
        "technique": "T1110 + T1046",
        "events": ssh_failures("198.51.100.30", 6, 5) + port_scan("198.51.100.30", 60),
        "expect": {"R003", "R002", "R004"},
    },
    {
        "name": "Força bruta lenta (evasão)",
        "technique": "T1110",
        "events": ssh_failures("198.51.100.40", 5, 70),
        "expect": {"R003"},
        "known_gap": True,
    },
]


def run_scenarios(rules):
    results = []
    for scenario in SCENARIOS:
        fired = {a["rule_id"] for a in evaluate(rules, scenario["events"])}
        results.append({
            "name": scenario["name"],
            "technique": scenario["technique"],
            "events": scenario["events"],
            "expect": scenario["expect"],
            "fired": fired,
            "ok": scenario["expect"] <= fired,
            "known_gap": scenario.get("known_gap", False),
        })
    return results


def main():
    results = run_scenarios(load_rules("rules"))
    for r in results:
        if r["ok"]:
            mark = "✔ detectado"
        elif r["known_gap"]:
            mark = "⚠ lacuna conhecida"
        else:
            mark = "✘ FALHOU"
        print(f"{mark:20} {r['name']} ({r['technique']}) -> disparou {sorted(r['fired'])}")

    with open("data/simulated.jsonl", "w") as f:
        for r in results:
            for e in r["events"]:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print("Eventos gravados em data/simulated.jsonl")


if __name__ == "__main__":
    main()
