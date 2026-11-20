import response


def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(response, "LOG_FILE", tmp_path / "log.jsonl")
    monkeypatch.setattr(response, "ALLOWLIST_FILE", tmp_path / "allow.txt")


def alert(severity, ip):
    return {
        "rule_id": "R003",
        "name": "teste",
        "severity": severity,
        "src_ip": ip,
        "timestamp": "2026-11-20T14:00:00+00:00",
    }


def test_dry_run_does_not_call_iptables(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)

    def fail(*args, **kwargs):
        raise AssertionError("iptables não deveria ser chamado")

    monkeypatch.setattr(response, "iptables", fail)
    entry = response.block_ip("198.51.100.10", "teste")
    assert entry["result"].startswith("simulado")


def test_loopback_is_protected(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    assert "protegido" in response.block_ip("127.0.0.1", "teste")["result"]


def test_allowlisted_ip_is_protected(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    (tmp_path / "allow.txt").write_text("# meu ip\n198.51.100.10\n")
    assert "protegido" in response.block_ip("198.51.100.10", "teste")["result"]


def test_invalid_ip(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    assert response.block_ip("nao-e-ip", "teste")["result"] == "ip inválido"


def test_respond_only_high_and_critical(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    alerts = [alert("low", "198.51.100.1"), alert("high", "198.51.100.2")]
    assert [e["ip"] for e in response.respond(alerts)] == ["198.51.100.2"]


def test_respond_blocks_each_ip_once(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    alerts = [alert("high", "198.51.100.2"), alert("critical", "198.51.100.2")]
    assert len(response.respond(alerts)) == 1
