"""End-to-end checks on every sample rule in data/rules."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from yagtha.analyzer import analyze
from yagtha.cli import default_benign_path, default_events_path, main
from yagtha.events import load_events
from yagtha.improver import improve
from yagtha.reporter import Verdict, verdict
from yagtha.rule_loader import load_rule
from yagtha.verifier import build_regression_cases, check_cases, verify

RULES = Path(__file__).resolve().parent.parent / "data" / "rules"

# rule file -> (evading before, evading after, notes not fixed)
EXPECTED = {
    "comsvcs_minidump.yml": (1, 0, 0),
    "mimikatz.yml": (1, 0, 0),
    "powershell_download_cradle.yml": (2, 1, 1),
    "whoami_discovery.yml": (2, 1, 1),
}


def test_every_sample_rule_is_covered() -> None:
    assert sorted(p.name for p in RULES.glob("*.yml")) == sorted(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_rule_end_to_end(name: str) -> None:
    path = RULES / name
    rule = load_rule(path)
    events = load_events(default_events_path(path))
    benign = load_events(default_benign_path(path))
    analysis = analyze(rule, events)
    assert analysis.undetected_baselines == ()
    improvement = improve(rule, analysis, events)
    result = verify(rule, improvement.new_rule, events, benign)
    before, after, unresolved = EXPECTED[name]
    assert len(result.original.evaded) == before
    assert len(result.improved.evaded) == after
    assert len(improvement.unresolved) == unresolved
    assert verdict(improvement, result) is Verdict.PASSED
    cases = build_regression_cases(result, benign)
    assert check_cases(improvement.new_rule, cases) == []


DEMO = Path(__file__).resolve().parent.parent / "examples" / "mimikatz_demo"


def test_mimikatz_demo_matches_a_fresh_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The committed demo is real output: a new run must produce the same files."""
    monkeypatch.chdir(tmp_path)
    assert main(["run", "--rule", str(RULES / "mimikatz.yml")], out=io.StringIO()) == 0
    bundle = tmp_path / "output" / "mimikatz"
    for name in (
        "original_rule.yml",
        "improved_rule.yml",
        "report.md",
        "regression_cases.json",
        "test_regression.py",
    ):
        expected = (DEMO / name).read_text("utf-8")
        assert (bundle / name).read_text("utf-8") == expected, name
