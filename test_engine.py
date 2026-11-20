from datetime import datetime, timedelta, timezone

from engine import evaluate

BASE = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)

SIMPLE = {
    "id": "T1", "name": "simples", "severity": "low",
    "match": {"source": "honeypot", "event_type": "ssh_login_failed"},
}

BRUTE = {
    "id": "T2", "name": "força bruta", "severity": "high",
    "match": {"source": "honeypot", "event_type": "ssh_login_failed"},
    "threshold": {"count": 5, "window_seconds": 120, "group_by": "src_ip"},
}


def ev(seconds, ip="1.1.1.1", source="honeypot", etype="ssh_login_failed"):
    return {
        "timestamp": (BASE + timedelta(seconds=seconds)).isoformat(),
        "source": source,
        "event_type": etype,
        "src_ip": ip,
        "details": {},
    }


def test_simple_rule_matches():
    assert len(evaluate([SIMPLE], [ev(0)])) == 1


def test_simple_rule_ignores_other_events():
    assert evaluate([SIMPLE], [ev(0, source="nids", etype="port_scan")]) == []


def test_threshold_fires_at_count():
    events = [ev(i * 10) for i in range(5)]
    alerts = evaluate([BRUTE], events)
    assert len(alerts) == 1
    assert alerts[0]["count"] == 5


def test_threshold_not_fired_below_count():
    events = [ev(i * 10) for i in range(4)]
    assert evaluate([BRUTE], events) == []


def test_threshold_respects_window():
    events = [ev(i * 60) for i in range(5)]
    assert evaluate([BRUTE], events) == []


def test_threshold_groups_by_ip():
    events = [ev(i * 5, ip="1.1.1.1") for i in range(3)]
    events += [ev(i * 5 + 1, ip="2.2.2.2") for i in range(3)]
    assert evaluate([BRUTE], events) == []


SCAN = {
    "id": "T4", "name": "scan", "severity": "medium",
    "match": {"source": "nids", "event_type": "port_scan"},
}

CORR = {
    "id": "T3", "name": "coordenado", "severity": "critical",
    "correlation": {"group_by": "src_ip", "window_seconds": 300, "requires": ["T2", "T4"]},
}


def brute_events(start, ip="1.1.1.1"):
    return [ev(start + i * 10, ip=ip) for i in range(5)]


def scan_event(seconds, ip="1.1.1.1"):
    return ev(seconds, ip=ip, source="nids", etype="port_scan")


def rule_ids(alerts):
    return {a["rule_id"] for a in alerts}


def test_correlation_fires_with_both_rules():
    alerts = evaluate([BRUTE, SCAN, CORR], brute_events(0) + [scan_event(100)])
    assert "T3" in rule_ids(alerts)


def test_correlation_needs_both_rules():
    alerts = evaluate([BRUTE, SCAN, CORR], brute_events(0))
    assert "T3" not in rule_ids(alerts)


def test_correlation_respects_window():
    alerts = evaluate([BRUTE, SCAN, CORR], brute_events(0) + [scan_event(1000)])
    assert "T3" not in rule_ids(alerts)


def test_correlation_requires_same_ip():
    events = brute_events(0, ip="1.1.1.1") + [scan_event(100, ip="2.2.2.2")]
    assert "T3" not in rule_ids(evaluate([BRUTE, SCAN, CORR], events))


def test_alert_carries_mitre():
    rule = {**SIMPLE, "mitre": [{"tactic": "Credential Access", "id": "T1110", "name": "Brute Force"}]}
    assert evaluate([rule], [ev(0)])[0]["mitre"][0]["id"] == "T1110"
