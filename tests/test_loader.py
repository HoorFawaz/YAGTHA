"""Tests for rule_loader: safe parsing and strict validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from yagtha.errors import RuleParseError, RuleValidationError, UnsupportedRuleFeatureError
from yagtha.models import Modifier, Rule
from yagtha.rule_loader import MAX_RULE_BYTES, load_rule, parse_rule

HEADER = """
title: Test rule
logsource:
  category: process_creation
  product: windows
"""


def rule_with(detection: str) -> str:
    """Build rule YAML around an indented detection block."""
    return HEADER + "detection:\n" + detection


def test_loads_mimikatz_rule(mimikatz_rule: Rule) -> None:
    assert mimikatz_rule.id == "6a1f3c52-2b7e-4d8a-9c41-0e5b7f2d9a13"
    assert mimikatz_rule.title == "Mimikatz Execution by Image Name"
    assert mimikatz_rule.level == "high"
    assert mimikatz_rule.condition == "selection"
    condition = mimikatz_rule.selections["selection"].alternatives[0][0]
    assert condition.field == "Image"
    assert condition.modifiers == (Modifier.ENDSWITH,)
    assert condition.values == ("\\mimikatz.exe",)


def test_missing_id_gets_slug_from_title() -> None:
    rule = parse_rule(rule_with("  sel:\n    Image: x\n  condition: sel\n"))
    assert rule.id == "test-rule"
    assert rule.level == "medium"


def test_list_of_maps_and_value_lists() -> None:
    rule = parse_rule(
        rule_with(
            "  sel:\n"
            "    - Image|endswith: ['\\a.exe', '\\b.exe']\n"
            "    - OriginalFileName: a.exe\n"
            "  condition: sel\n"
        )
    )
    selection = rule.selections["sel"]
    assert len(selection.alternatives) == 2
    assert selection.alternatives[0][0].values == ("\\a.exe", "\\b.exe")
    assert selection.fields == ("Image", "OriginalFileName")


def test_condition_list_is_combined_with_or() -> None:
    rule = parse_rule(rule_with("  a:\n    Image: x\n  b:\n    Image: y\n  condition: [a, b]\n"))
    assert rule.condition == "(a) or (b)"


def test_python_tags_are_rejected_by_safe_load() -> None:
    text = rule_with("  sel: !!python/object/apply:os.system ['echo hi']\n  condition: sel\n")
    with pytest.raises(RuleParseError):
        parse_rule(text)


def test_invalid_yaml() -> None:
    with pytest.raises(RuleParseError):
        parse_rule("title: [unclosed")


def test_multiple_documents_are_rejected() -> None:
    with pytest.raises(RuleParseError):
        parse_rule(rule_with("  sel:\n    Image: x\n  condition: sel\n") + "---\ntitle: two\n")


def test_rule_must_be_a_mapping() -> None:
    with pytest.raises(RuleValidationError):
        parse_rule("- just\n- a list\n")


def test_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.yml"
    path.write_text("#" * (MAX_RULE_BYTES + 1), encoding="utf-8")
    with pytest.raises(RuleParseError, match="larger than"):
        load_rule(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuleParseError, match="cannot read"):
        load_rule(tmp_path / "nope.yml")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("logsource: {category: process_creation, product: windows}\n", "title"),
        (HEADER + "level: severe\ndetection:\n  sel: {Image: x}\n  condition: sel\n", "level"),
        (HEADER, "detection"),
        (rule_with("  condition: sel\n"), "no selections"),
        (rule_with("  sel:\n    Image: x\n"), "condition"),
        (rule_with("  sel:\n    Image: x\n  condition: other\n"), "unknown selection"),
        (rule_with("  sel:\n    Image: x\n  condition: sel and\n"), "ends unexpectedly"),
        (rule_with("  sel:\n    Image: x\n  condition: (sel\n"), "ends unexpectedly"),
        (rule_with("  sel:\n    Image: x\n  condition: sel )\n"), "unexpected"),
        (rule_with("  sel:\n    Image: x\n  condition: sel & sel\n"), "invalid character"),
        (rule_with("  sel:\n    Image: x\n  condition: 1 of nothing*\n"), "matches no"),
        (rule_with("  sel:\n    Image: {a: b}\n  condition: sel\n"), "values must be"),
        (rule_with("  sel:\n    Image: []\n  condition: sel\n"), "no values"),
        (rule_with("  sel: {}\n  condition: sel\n"), "empty mapping"),
        (rule_with("  sel: 5\n  condition: sel\n"), "mapping or a list"),
        (rule_with("  sel:\n    'Ima ge': x\n  condition: sel\n"), "invalid field name"),
        (rule_with("  sel:\n    Image|contains|endswith: x\n  condition: sel\n"), "only one"),
        (rule_with("  sel:\n    Image|all|all: x\n  condition: sel\n"), "repeated"),
        (rule_with("  sel:\n    Image|re: '(unclosed'\n  condition: sel\n"), "invalid regex"),
        (rule_with("  sel:\n    Image|re: 5\n  condition: sel\n"), "must be strings"),
        (
            "title: t\nlogsource: {category: process_creation, product: [windows]}\n"
            "detection:\n  sel: {Image: x}\n  condition: sel\n",
            "must be strings",
        ),
    ],
)
def test_validation_errors(text: str, message: str) -> None:
    with pytest.raises(RuleValidationError, match=message):
        parse_rule(text)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "title: t\nlogsource: {category: file_event, product: windows}\n"
            "detection:\n  sel: {Image: x}\n  condition: sel\n",
            "only",
        ),
        (rule_with("  sel:\n    Image|base64offset: x\n  condition: sel\n"), "base64offset"),
        (rule_with("  keywords:\n    - mimikatz\n  condition: keywords\n"), "keyword"),
        (rule_with("  sel:\n    Image: x\n  timeframe: 5m\n  condition: sel\n"), "timeframe"),
        (rule_with("  sel:\n    Image: x\n  condition: sel | count() > 5\n"), "aggregation"),
        (rule_with("  sel:\n    Image: x\n  condition: 2 of sel\n"), "'2 of'"),
        (rule_with("  sel:\n    Image|re: '(a+)+$'\n  condition: sel\n"), "nested quantifiers"),
    ],
)
def test_unsupported_features_raise_clearly(text: str, message: str) -> None:
    with pytest.raises(UnsupportedRuleFeatureError, match=message):
        parse_rule(text)


def test_regex_length_limit() -> None:
    with pytest.raises(RuleValidationError, match="longer than"):
        parse_rule(rule_with(f"  sel:\n    Image|re: '{'a' * 600}'\n  condition: sel\n"))


def test_condition_nesting_limit() -> None:
    deep = "(" * 40 + "sel" + ")" * 40
    with pytest.raises(RuleValidationError, match="nested deeper"):
        parse_rule(rule_with(f"  sel:\n    Image: x\n  condition: '{deep}'\n"))
