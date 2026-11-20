from engine import load_rules
from simulator import run_scenarios


def test_scenarios_detect_as_expected():
    for result in run_scenarios(load_rules("rules")):
        if result["known_gap"]:
            assert not result["ok"]
        else:
            assert result["ok"], result["name"]
