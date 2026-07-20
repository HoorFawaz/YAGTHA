"""Tests for the rule improver."""

from __future__ import annotations

from typing import Any

from yagtha.analyzer import analyze
from yagtha.evaluator import matches
from yagtha.improver import escape_value, filter_names, improve, significant_arguments
from yagtha.models import Rule
from yagtha.mutations import get_mutation
from yagtha.rule_loader import parse_rule

HEADER = """
title: Test Rule
id: test-rule
logsource:
  category: process_creation
  product: windows
level: high
detection:
"""


def make_rule(detection: str) -> Rule:
    return parse_rule(HEADER + detection)


def test_mimikatz_rule_gets_original_file_name_and_command_line(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    analysis = analyze(mimikatz_rule, [mimikatz_event])
    improvement = improve(mimikatz_rule, analysis, [mimikatz_event])
    assert improvement.changed
    assert improvement.unresolved == ()
    new = improvement.new_rule
    assert set(new.selections) == {"selection", "yagtha_original_file_name", "yagtha_command_line"}
    assert new.condition == "(selection) or (yagtha_original_file_name or yagtha_command_line)"
    assert new.title.endswith("(improved by YAGTHA)")
    assert new.raw["related"] == [{"id": mimikatz_rule.id, "type": "derived"}]
    renamed = get_mutation("rename_image").apply(mimikatz_event)
    assert renamed is not None
    assert not matches(mimikatz_rule, renamed)
    assert matches(new, renamed)
    assert "privilege::debug" in improvement.yaml_text


def test_improvement_is_deterministic_and_reparses(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    analysis = analyze(mimikatz_rule, [mimikatz_event])
    first = improve(mimikatz_rule, analysis, [mimikatz_event])
    second = improve(mimikatz_rule, analysis, [mimikatz_event])
    assert first.yaml_text == second.yaml_text
    assert first.new_rule.id == second.new_rule.id != mimikatz_rule.id
    assert parse_rule(first.yaml_text) == first.new_rule


def test_no_evasion_leaves_rule_unchanged(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    analysis = analyze(mimikatz_rule, [mimikatz_event], ["change_case"])
    improvement = improve(mimikatz_rule, analysis, [mimikatz_event])
    assert not improvement.changed
    assert improvement.new_rule is mimikatz_rule
    assert improvement.yaml_text == ""
    assert "unchanged" in improvement.rationale


def test_filters_are_kept_and_filter_evasion_is_unresolved(
    mimikatz_event: dict[str, Any],
) -> None:
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\mimikatz.exe'
  filter_explorer:
    ParentImage|endswith: '\\explorer.exe'
  condition: selection and not filter_explorer
"""
    )
    analysis = analyze(rule, [mimikatz_event], ["rename_image", "alt_parent"])
    improvement = improve(rule, analysis, [mimikatz_event])
    assert "and not filter_explorer" in improvement.new_rule.condition
    assert any("kept the filters" in change for change in improvement.changes)
    assert len(improvement.unresolved) == 1
    assert "alt_parent: filter 'filter_explorer'" in improvement.unresolved[0]
    moved = get_mutation("alt_parent").apply(mimikatz_event)
    assert moved is not None
    assert not matches(improvement.new_rule, moved)


def test_exact_image_rule_gets_image_name_and_rename_is_unresolved() -> None:
    event = {"Image": "C:\\Users\\analyst\\Downloads\\mimikatz.exe"}
    rule = make_rule(
        """
  selection:
    Image: 'C:\\Users\\analyst\\Downloads\\mimikatz.exe'
  condition: selection
"""
    )
    analysis = analyze(rule, [event], ["change_path", "rename_image"])
    improvement = improve(rule, analysis, [event])
    assert set(improvement.new_rule.selections) == {"selection", "yagtha_image_name"}
    moved = get_mutation("change_path").apply(event)
    assert moved is not None
    assert matches(improvement.new_rule, moved)
    assert improvement.unresolved == (
        "rename_image: no unchanged field shows the behaviour, so there is no safe value "
        "to match on",
    )


def test_only_unresolved_evasions_give_no_change() -> None:
    event = {"Image": "C:\\Tools\\mimikatz.exe"}
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\mimikatz.exe'
  condition: selection
"""
    )
    analysis = analyze(rule, [event], ["rename_image"])
    improvement = improve(rule, analysis, [event])
    assert not improvement.changed
    assert "No automatic fix" in improvement.rationale
    assert len(improvement.unresolved) == 1


def test_values_come_only_from_detected_baselines(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    other = {"Image": "C:\\Windows\\notepad.exe", "OriginalFileName": "NOTEPAD.EXE"}
    events = [mimikatz_event, other]
    analysis = analyze(mimikatz_rule, events, ["rename_image"])
    improvement = improve(mimikatz_rule, analysis, events)
    assert "NOTEPAD" not in improvement.yaml_text
    assert not matches(improvement.new_rule, other)


def test_selection_names_do_not_collide(mimikatz_event: dict[str, Any]) -> None:
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\mimikatz.exe'
  yagtha_original_file_name:
    User: 'nobody'
  condition: selection or yagtha_original_file_name
"""
    )
    analysis = analyze(rule, [mimikatz_event], ["rename_image"])
    improvement = improve(rule, analysis, [mimikatz_event])
    assert "yagtha_original_file_name_2" in improvement.new_rule.selections
    assert improvement.new_rule.selections["yagtha_original_file_name"].fields == ("User",)


def test_significant_arguments() -> None:
    line = 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
    assert significant_arguments(line) == ["privilege::debug", "sekurlsa::logonpasswords"]
    assert significant_arguments("cmd.exe /c dir C:\\Users -Flag") == []
    assert significant_arguments("tool.exe a-b-c-d e f gh longplainword") == [
        "a-b-c-d",
        "longplainword",
    ]
    assert significant_arguments("tool.exe *.txt") == ["\\*.txt"]
    assert significant_arguments(None) == []
    assert len(significant_arguments("t.exe " + " ".join(f"arg::{i}" for i in range(9)))) == 4


def test_escape_value() -> None:
    assert escape_value("plain\\path.exe") == "plain\\path.exe"
    assert escape_value("a*b?c") == "a\\*b\\?c"
    assert escape_value("end\\*") == "end\\\\\\*"
    assert escape_value("two\\\\") == "two\\\\\\"


def test_filter_names() -> None:
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\a.exe'
  filter_one:
    User: 'x'
  filter_two:
    User: 'y'
  condition: selection and not (filter_one or filter_two) and not not selection
"""
    )
    assert filter_names(rule) == ("filter_one", "filter_two")
    of_rule = make_rule(
        """
  selection:
    Image|endswith: '\\a.exe'
  filter_one:
    User: 'x'
  condition: selection and not 1 of filter_*
"""
    )
    assert filter_names(of_rule) == ("filter_one",)
