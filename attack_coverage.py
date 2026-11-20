import json
from pathlib import Path

from engine import load_rules
from simulator import run_scenarios

TARGETS = {
    "T1110": "Brute Force",
    "T1046": "Network Service Discovery",
    "T1498": "Network Denial of Service",
    "T1566": "Phishing",
}


def technique_map(rules):
    covered = {}
    for rule in rules:
        for m in rule.get("mitre", []):
            covered.setdefault(m["id"], set()).add(rule["id"])
    return covered


def validated_techniques(rules, results):
    by_id = {rule["id"]: rule for rule in rules}
    validated = set()
    for result in results:
        if not result["ok"]:
            continue
        for rule_id in result["expect"]:
            for m in by_id[rule_id].get("mitre", []):
                validated.add(m["id"])
    return validated


def main():
    rules = load_rules("rules")
    results = run_scenarios(rules)
    covered = technique_map(rules)
    validated = validated_techniques(rules, results)

    rows = []
    print(f"{'Técnica':8} {'Nome':28} {'Regras':16} Status")
    for tech_id, name in TARGETS.items():
        rule_ids = sorted(covered.get(tech_id, []))
        if tech_id in validated:
            status = "validada"
        elif rule_ids:
            status = "com regra, sem teste"
        else:
            status = "SEM COBERTURA"
        print(f"{tech_id:8} {name:28} {','.join(rule_ids) or '-':16} {status}")
        rows.append({"id": tech_id, "name": name, "rules": rule_ids, "status": status})

    total = len(rows)
    with_rule = sum(1 for r in rows if r["rules"])
    done = sum(1 for r in rows if r["status"] == "validada")
    print(f"\nCobertura: {with_rule}/{total} ({with_rule * 100 // total}%) | Validadas por simulação: {done}/{total} ({done * 100 // total}%)")

    summary = {"techniques": rows, "with_rule": with_rule, "validated": done, "total": total}
    Path("data/coverage.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
