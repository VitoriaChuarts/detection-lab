import argparse
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from engine import evaluate, load_rules
from enrichment import enrich_ip, load_cache, save_cache
from event_model import load_events

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
HOME_TZ = "America/Sao_Paulo"
WIDTH = 74


def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["xxx"])
    return ip[:12] + "…"


def convert(timestamp, tz_name):
    if not tz_name:
        return "n/d"
    try:
        moment = datetime.fromisoformat(timestamp).astimezone(ZoneInfo(tz_name))
    except (KeyError, ValueError, OSError):
        return "n/d"
    return moment.strftime("%d/%m/%Y %H:%M:%S")


def yes_no(value):
    if value is None:
        return "n/d"
    return "sim" if value else "não"


def build_card(ip, alerts, events, info, mask=True):
    events = sorted(events, key=lambda e: e["timestamp"])
    first, last = events[0]["timestamp"], events[-1]["timestamp"]
    seconds = int((datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds())
    top = max(alerts, key=lambda a: RANK[a["severity"]])
    techniques = sorted({m["id"] for a in alerts for m in a["mitre"]})
    place = ", ".join(p for p in (info.get("city"), info.get("regionName"), info.get("country")) if p)
    tz_name = info.get("timezone", "")

    rows = [
        ("IP", mask_ip(ip) if mask else ip),
        ("Localização", place or info.get("scope", "n/d")),
        ("Provedor", info.get("isp", "n/d")),
        ("ASN", info.get("as", "n/d")),
        ("Datacenter / VPS", yes_no(info.get("hosting"))),
        ("Proxy / VPN", yes_no(info.get("proxy"))),
    ]
    if "abuse_score" in info:
        rows.append(("Reputação (AbuseIPDB)", f"{info['abuse_score']}/100"))
    rows += [
        ("Fuso do atacante", tz_name or "n/d"),
        ("Início (UTC)", convert(first, "UTC")),
        ("Início (Brasília)", convert(first, HOME_TZ)),
        ("Início (hora local dele)", convert(first, tz_name)),
        ("Duração", f"{seconds} s"),
        ("Eventos observados", str(len(events))),
        ("Severidade máxima", top["severity"].upper()),
        ("Técnicas ATT&CK", ", ".join(techniques) or "-"),
    ]

    line = "─" * WIDTH
    out = [line, "  FICHA DO ATACANTE"]
    if info.get("simulated"):
        out.append("  ⚠ dados geográficos SIMULADOS (demonstração)")
    out.append(line)
    for label, value in rows:
        out.append(f"  {label:26} {value}")
    out.append(line)
    out.append("  * Geolocalização por IP é aproximada e não identifica pessoas.")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Ficha do atacante: local, horários e técnicas")
    parser.add_argument("ip", nargs="?", help="IP do atacante (padrão: o de maior severidade)")
    parser.add_argument("--events", default="data/simulated.jsonl")
    parser.add_argument("--full", action="store_true", help="mostra o IP completo (não use em posts)")
    args = parser.parse_args()

    events = load_events(args.events)
    alerts = evaluate(load_rules("rules"), events)
    if not alerts:
        sys.exit("Nenhum alerta nesse arquivo de eventos.")

    ip = args.ip or max(alerts, key=lambda a: RANK[a["severity"]])["src_ip"]
    ip_alerts = [a for a in alerts if a["src_ip"] == ip]
    ip_events = [e for e in events if e["src_ip"] == ip]
    if not ip_alerts:
        sys.exit(f"Nenhum alerta para o IP {ip}.")

    cache = load_cache()
    info = enrich_ip(ip, cache)
    save_cache(cache)
    print(build_card(ip, ip_alerts, ip_events, info, mask=not args.full))


if __name__ == "__main__":
    main()
