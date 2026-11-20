from siem_client import build_payload

ALERT = {
    "rule_id": "R003", "name": "Força bruta SSH", "severity": "high",
    "src_ip": "198.51.100.10", "timestamp": "2026-11-20T15:00:25+00:00", "count": 5,
    "mitre": [{"tactic": "Credential Access", "id": "T1110", "name": "Brute Force"}],
}


def test_payload_fields():
    payload = build_payload(ALERT, {"scope": "publico", "country": "Brasil"}, {"result": "simulado: iptables"})
    assert payload["detectedAt"] == "2026-11-20T15:00:25Z"
    assert payload["techniques"] == "T1110"
    assert payload["country"] == "Brasil"
    assert payload["response"] == "simulado: iptables"


def test_payload_without_action_and_geo():
    payload = build_payload(ALERT, {"scope": "privado/reservado"}, None)
    assert payload["country"] == "privado/reservado"
    assert payload["response"] == ""
