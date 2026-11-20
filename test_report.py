from report import build_report

ALERTS = [{
    "rule_id": "R003", "name": "Força bruta SSH", "severity": "high",
    "src_ip": "1.1.1.1", "timestamp": "2026-11-20T14:00:18+00:00", "count": 5,
    "mitre": [{"tactic": "Credential Access", "id": "T1110", "name": "Brute Force"}],
    "related": [],
}]

EVENTS = [{
    "timestamp": "2026-11-20T14:00:01+00:00", "source": "honeypot",
    "event_type": "ssh_login_failed", "src_ip": "1.1.1.1", "details": {},
}]


def test_report_has_key_sections():
    text = build_report("1.1.1.1", ALERTS, EVENTS, [], {"scope": "publico", "country": "Brasil"})
    assert "# Relatório de incidente" in text
    assert "HIGH" in text
    assert "T1110" in text
    assert "Brasil" in text
