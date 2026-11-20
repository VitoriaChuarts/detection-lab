import json
import urllib.request


def build_payload(alert, info, action=None):
    return {
        "ruleId": alert["rule_id"],
        "ruleName": alert["name"],
        "severity": alert["severity"],
        "srcIp": alert["src_ip"],
        "detectedAt": alert["timestamp"].replace("+00:00", "Z"),
        "eventCount": alert["count"],
        "techniques": ",".join(m["id"] for m in alert["mitre"]),
        "country": info.get("country") or info.get("scope", ""),
        "response": action["result"] if action else "",
    }


def post_json(url, api_key, body):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode() or "{}")
