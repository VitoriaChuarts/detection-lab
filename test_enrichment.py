from enrichment import enrich_ip


def test_private_ip_is_not_looked_up():
    assert enrich_ip("192.168.1.10", {})["scope"] == "privado/reservado"


def test_invalid_ip():
    assert enrich_ip("nao-e-ip", {})["scope"] == "invalido"


def test_cache_is_used():
    cache = {"8.8.8.8": {"scope": "publico", "country": "X"}}
    assert enrich_ip("8.8.8.8", cache)["country"] == "X"
