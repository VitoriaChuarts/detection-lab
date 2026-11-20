import argparse
import json
import os
import sys
import urllib.error
from pathlib import Path

from engine import evaluate, load_rules
from enrichment import enrich_ip, load_cache, save_cache
from event_model import load_events
from response import respond
from siem_client import build_payload, post_json

BATCH = 200


def main():
    parser = argparse.ArgumentParser(description="Envia alertas e cobertura ATT&CK ao mini-SIEM")
    parser.add_argument("events", nargs="?", default="data/simulated.jsonl")
    parser.add_argument("--url", default="http://localhost:8080")
    args = parser.parse_args()

    api_key = os.environ.get("SIEM_API_KEY")
    if not api_key:
        sys.exit("Defina SIEM_API_KEY primeiro: export SIEM_API_KEY=$(cat ~/.siem_key)")

    alerts = evaluate(load_rules("rules"), load_events(args.events))
    cache = load_cache()
    infos = {ip: enrich_ip(ip, cache) for ip in {a["src_ip"] for a in alerts}}
    save_cache(cache)
    actions = {x["ip"]: x for x in respond(alerts)}
    payload = [build_payload(a, infos[a["src_ip"]], actions.get(a["src_ip"])) for a in alerts]

    try:
        saved = skipped = 0
        for i in range(0, len(payload), BATCH):
            result = post_json(f"{args.url}/api/detections", api_key, payload[i:i + BATCH])
            saved += result["saved"]
            skipped += result["skipped"]
        print(f"Alertas enviados: {saved} novos, {skipped} já existiam")

        coverage_file = Path("data/coverage.json")
        if coverage_file.exists():
            post_json(f"{args.url}/api/detections/coverage", api_key, json.loads(coverage_file.read_text()))
            print("Cobertura ATT&CK enviada")
        else:
            print("data/coverage.json não existe: rode attack_coverage.py antes")
    except urllib.error.HTTPError as error:
        sys.exit(f"O SIEM recusou a requisição: HTTP {error.code}")
    except urllib.error.URLError as error:
        sys.exit(f"Não consegui conectar ao SIEM em {args.url}: {error.reason}")


if __name__ == "__main__":
    main()
