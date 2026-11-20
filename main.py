import argparse

from engine import evaluate, load_rules
from enrichment import enrich_ip, load_cache, save_cache
from event_model import load_events
from report import write_reports
from response import respond


def main():
    parser = argparse.ArgumentParser(description="Detection Engineering Lab")
    parser.add_argument("events", nargs="?", default="data/sample.jsonl", help="arquivo .jsonl de eventos")
    parser.add_argument("--apply", action="store_true", help="bloqueia IPs de verdade (padrão: simulação)")
    args = parser.parse_args()

    rules = load_rules("rules")
    events = load_events(args.events)
    alerts = evaluate(rules, events)

    cache = load_cache()
    enrichments = {ip: enrich_ip(ip, cache) for ip in {a["src_ip"] for a in alerts}}
    save_cache(cache)

    for a in alerts:
        info = enrichments[a["src_ip"]]
        where = info.get("country", info.get("scope", "?"))
        techniques = ", ".join(m["id"] for m in a["mitre"]) or "-"
        print(f"[{a['severity'].upper()}] {a['rule_id']} - {a['name']} | ip={a['src_ip']} ({where}) | ATT&CK: {techniques}")

    actions = respond(alerts, apply=args.apply)
    for act in actions:
        print(f"  RESPOSTA {act['ip']}: {act['result']}")

    for path in write_reports(alerts, events, actions, enrichments):
        print(f"  Relatório: {path}")


if __name__ == "__main__":
    main()
