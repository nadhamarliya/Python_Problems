import pytest
from solution import (add_finding, make_multipliers, drop_info, is_same_rule,
                   clone_report, budget_met, average)

def test_add_finding():
    first = add_finding("a")
    second = add_finding("b")

    assert first == ['a']
    assert second == ['b']

def test_make_multipliers():
    result = [f(10) for f in make_multipliers()]
    assert result == [0, 10, 20]

@pytest.mark.parametrize( "findings, expected",  [
    ([{"sev":"info"}, {"sev":"high"}], [{"sev":"high"}]),
    ([{"sev":"info"}, {"sev":"info"}, {"sev":"high"}], [{"sev":"high"}]),
    ([{"sev":"info"}, {"sev":"info"}, {"sev":"info"}], []),
])
def test_drop_info(findings, expected):
    result = drop_info(findings)
    assert result == expected

def test_is_same_rule():
    a = "".join(["sem", "grep"])
    b = "semgrep"

    assert is_same_rule(a,b) is True

def test_clone_report():
    r = {"files": ["a.py"]}
    c = clone_report(r)
    c["files"].append("b.py")

    assert r["files"] == ["a.py"]

def test_budget_met():
    assert budget_met([0.1, 0.2]) is True

def test_average():
    assert average(7, 2) == 3.5

