"""Tests for the verifier and regression cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from yagtha.analyzer import analyze
from yagtha.errors import EventValidationError
from yagtha.events import load_events
from yagtha.improver import improve
from yagtha.models import Expected, RegressionCase, Rule
from yagtha.rule_loader import parse_rule
from yagtha.verifier import (
    MAX_CASES,
    build_regression_cases,
    cases_from_dict,
    cases_to_dict,
    check_cases,
    verify,
)

BENIGN = Path(__file__).resolve().parent.parent / "data" / "benign_events" / "benign.json"


def make_rule(detection: str) -> Rule:
    return parse_rule(
        "title: Candidate\nlogsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n" + detection
    )


@pytest.fixture
def benign() -> list[dict[str, Any]]:
    return load_events(BENIGN)


@pytest.fixture
def improved(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> Rule:
    analysis = analyze(mimikatz_rule, [mimikatz_event])
    return improve(mimikatz_rule, analysis, [mimikatz_event]).new_rule


def test_benign_corpus_is_valid_and_quiet(mimikatz_rule: Rule, benign: list[Any]) -> None:
    assert len(benign) >= 10
    result = verify(mimikatz_rule, mimikatz_rule, [], benign)
    assert result.benign_hits_original == ()


def test_improved_mimikatz_rule_passes(
    mimikatz_rule: Rule, improved: Rule, mimikatz_event: dict[str, Any], benign: list[Any]
) -> None:
    result = verify(mimikatz_rule, improved, [mimikatz_event], benign)
    assert result.passed
    assert result.fixed == ("event0/rename_image",)
    assert result.improved.evaded == ()
    assert result.regressions == ()
    assert result.benign_total == len(benign)
    assert result.new_false_positives == ()


def test_new_false_positive_fails_verification(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any], benign: list[Any]
) -> None:
    # A naive "fix": any command line mentioning mimikatz. It also fires on
    # the analyst opening their notes in notepad.
    naive = make_rule(
        "  selection:\n    CommandLine|contains: 'mimikatz'\n  condition: selection\n"
    )
    result = verify(mimikatz_rule, naive, [mimikatz_event], benign)
    assert result.new_false_positives == (0,)
    assert result.regressions == ()
    assert not result.passed


def test_regressions_are_reported(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    narrow = make_rule("  selection:\n    User: 'LAB\\\\nobody'\n  condition: selection\n")
    result = verify(mimikatz_rule, narrow, [mimikatz_event], [])
    assert "event0/original is no longer detected" in result.regressions
    assert not result.passed


def test_regression_cases_lock_in_the_improvement(
    mimikatz_rule: Rule, improved: Rule, mimikatz_event: dict[str, Any], benign: list[Any]
) -> None:
    result = verify(mimikatz_rule, improved, [mimikatz_event], benign)
    cases = build_regression_cases(result, benign)
    matching = [c for c in cases if c.expected is Expected.MATCH]
    assert len(matching) == len(result.improved.outcomes)
    assert len(cases) - len(matching) == len(benign)
    assert check_cases(improved, cases) == []
    assert check_cases(mimikatz_rule, cases) == [
        "event0-rename_image: expected match but the rule did not fire"
    ]


def test_cases_leave_out_what_the_improved_rule_gets_wrong(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any], benign: list[Any]
) -> None:
    result = verify(mimikatz_rule, mimikatz_rule, [mimikatz_event], benign)
    names = {c.name for c in build_regression_cases(result, benign)}
    assert "event0-rename_image" not in names
    assert "event0-original" in names


def test_cases_round_trip_through_json(
    mimikatz_rule: Rule, improved: Rule, mimikatz_event: dict[str, Any], benign: list[Any]
) -> None:
    result = verify(mimikatz_rule, improved, [mimikatz_event], benign)
    cases = build_regression_cases(result, benign)
    data = json.loads(json.dumps(cases_to_dict(improved, cases)))
    assert data["rule_id"] == improved.id
    assert cases_from_dict(data) == cases


def test_escaped_wildcards_match_literally() -> None:
    rule = make_rule(
        "  selection:\n    CommandLine|contains|all:\n    - '\\*.txt'\n  condition: selection\n"
    )
    cases = (
        RegressionCase("star", Expected.MATCH, {"CommandLine": "type *.txt"}),
        RegressionCase("no-star", Expected.NO_MATCH, {"CommandLine": "type a.txt"}),
    )
    assert check_cases(rule, cases) == []


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"cases": "x"},
        {"cases": ["x"]},
        {"cases": [{"name": "", "expected": "match", "event": {}}]},
        {"cases": [{"name": "a", "expected": "maybe", "event": {}}]},
        {"cases": [{"name": "a", "expected": "match", "event": {"A": {"nested": 1}}}]},
        {"cases": [{"name": "a", "expected": "match", "event": {}}] * (MAX_CASES + 1)},
    ],
)
def test_invalid_case_files_are_rejected(data: Any) -> None:
    with pytest.raises(EventValidationError):
        cases_from_dict(data)
