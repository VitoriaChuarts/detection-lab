from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REPORT_FROM = "high"


def origin_text(info):
    parts = [info[key] for key in ("country", "city", "isp") if key in info]
    text = ", ".join(parts) or info.get("scope", "desconhecida")
    if "abuse_score" in info:
        text += f" (reputação AbuseIPDB: {info['abuse_score']}/100)"
    return text


def build_report(ip, alerts, events, actions, info):
    alerts = sorted(alerts, key=lambda a: a["timestamp"])
    events = sorted(events, key=lambda e: e["timestamp"])
    top = max(alerts, key=lambda a: RANK[a["severity"]])["severity"].upper()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines = [
        f"# Relatório de incidente — {ip}",
        "",
        f"- **Gerado em:** {now}",
        f"- **Severidade máxima:** {top}",
        f"- **Origem:** {origin_text(info)}",
    ]
    if events:
        lines.append(f"- **Primeira atividade:** {events[0]['timestamp']}")
        lines.append(f"- **Última atividade:** {events[-1]['timestamp']}")

    lines += ["", "## Resumo da atividade", "", "| Fonte | Evento | Quantidade |", "|---|---|---|"]
    counts = Counter((e["source"], e["event_type"]) for e in events)
    for (source, event_type), total in sorted(counts.items()):
        lines.append(f"| {source} | {event_type} | {total} |")

    lines += ["", "## Linha do tempo dos alertas", "", "| Horário | Severidade | Regra | Técnicas |", "|---|---|---|---|"]
    for a in alerts:
        tech_ids = ", ".join(m["id"] for m in a["mitre"]) or "-"
        lines.append(f"| {a['timestamp']} | {a['severity'].upper()} | {a['rule_id']} - {a['name']} | {tech_ids} |")

    techniques = {}
    for a in alerts:
        for m in a["mitre"]:
            techniques[m["id"]] = m
    lines += ["", "## Técnicas MITRE ATT&CK observadas", ""]
    for tech_id, m in sorted(techniques.items()):
        lines.append(f"- **{tech_id}** {m['name']} ({m['tactic']})")

    lines += ["", "## Resposta automática", ""]
    if actions:
        for act in actions:
            lines.append(f"- {act['timestamp']} — modo {act['mode']}: {act['result']}")
    else:
        lines.append("- Nenhuma ação registrada.")
    return "\n".join(lines) + "\n"


def write_reports(alerts, events, actions, enrichments, folder="reports"):
    Path(folder).mkdir(exist_ok=True)
    paths = []
    for ip in sorted({a["src_ip"] for a in alerts}):
        ip_alerts = [a for a in alerts if a["src_ip"] == ip]
        if max(RANK[a["severity"]] for a in ip_alerts) < RANK[REPORT_FROM]:
            continue
        ip_events = [e for e in events if e["src_ip"] == ip]
        ip_actions = [x for x in actions if x["ip"] == ip]
        text = build_report(ip, ip_alerts, ip_events, ip_actions, enrichments.get(ip, {}))
        path = Path(folder) / f"incident_{ip.replace(':', '_')}.md"
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths
