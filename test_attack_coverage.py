from attack_coverage import technique_map, validated_techniques

RULES = [
    {"id": "A", "mitre": [{"id": "T1", "name": "n", "tactic": "t"}]},
    {"id": "B", "mitre": [{"id": "T1", "name": "n", "tactic": "t"}, {"id": "T2", "name": "m", "tactic": "t"}]},
]


def test_technique_map_groups_rules():
    assert technique_map(RULES) == {"T1": {"A", "B"}, "T2": {"B"}}


def test_validated_only_from_passing_scenarios():
    results = [{"ok": True, "expect": {"A"}}, {"ok": False, "expect": {"B"}}]
    assert validated_techniques(RULES, results) == {"T1"}
