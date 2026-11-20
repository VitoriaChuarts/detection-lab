import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("data/response_log.jsonl")
ALLOWLIST_FILE = Path("data/allowlist.txt")
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCK_FROM = "high"


def load_allowlist():
    if not ALLOWLIST_FILE.exists():
        return set()
    lines = ALLOWLIST_FILE.read_text().splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def log_action(entry):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def iptables(flag, ip):
    return subprocess.run(
        ["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True,
    )


def block_ip(ip, reason, apply=False):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": ip,
        "reason": reason,
        "mode": "apply" if apply else "dry-run",
        "result": "",
    }
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        entry["result"] = "ip inválido"
        return log_action(entry)

    ip = str(addr)
    entry["ip"] = ip
    if addr.is_loopback or ip in load_allowlist():
        entry["result"] = "ignorado (IP protegido)"
    elif not apply:
        entry["result"] = f"simulado: iptables -I INPUT -s {ip} -j DROP"
    elif iptables("-C", ip).returncode == 0:
        entry["result"] = "já estava bloqueado"
    else:
        result = iptables("-I", ip)
        entry["result"] = "bloqueado" if result.returncode == 0 else f"erro: {result.stderr.strip()}"
    return log_action(entry)


def respond(alerts, apply=False):
    actions = []
    done = set()
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        if RANK[alert["severity"]] < RANK[BLOCK_FROM] or alert["src_ip"] in done:
            continue
        done.add(alert["src_ip"])
        reason = f"{alert['rule_id']} - {alert['name']}"
        actions.append(block_ip(alert["src_ip"], reason, apply))
    return actions
