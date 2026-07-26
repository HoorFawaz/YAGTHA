"""Tests for the rule improver."""

from __future__ import annotations

from typing import Any

from yagtha.analyzer import analyze
from yagtha.condition import parse_condition
from yagtha.evaluator import matches
from yagtha.improver import escape_value, improve, render_condition, significant_arguments
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
    assert list(new.selections) == ["selection", "yagtha_selection"]
    assert new.condition == "selection or yagtha_selection"
    added = new.raw["detection"]["yagtha_selection"]
    assert added == [
        {"OriginalFileName": "mimikatz.exe"},
        {"CommandLine|contains|all": ["privilege::debug", "sekurlsa::logonpasswords"]},
    ]
    assert new.title.endswith("(improved by YAGTHA)")
    assert new.raw["related"] == [{"id": mimikatz_rule.id, "type": "derived"}]
    renamed = get_mutation("rename_image").apply(mimikatz_event)
    assert renamed is not None
    assert not matches(mimikatz_rule, renamed)
    assert matches(new, renamed)


def test_other_fields_of_the_selection_are_kept() -> None:
    event = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "powershell.exe -Command DownloadString",
    }
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'DownloadString'
  condition: selection
"""
    )
    analysis = analyze(rule, [event], ["rename_image"])
    improvement = improve(rule, analysis, [event])
    assert improvement.new_rule.raw["detection"]["yagtha_selection"][0] == {
        "CommandLine|contains": "DownloadString",
        "OriginalFileName": "PowerShell.EXE",
    }
    other = {"OriginalFileName": "PowerShell.EXE", "CommandLine": "powershell.exe Get-Date"}
    assert not matches(improvement.new_rule, other)


def test_encoded_command_is_insufficient_evidence() -> None:
    event = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "powershell.exe -Command DownloadString",
    }
    rule = make_rule(
        """
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'DownloadString'
  condition: selection
"""
    )
    analysis = analyze(rule, [event], ["encode_cmdline"])
    improvement = improve(rule, analysis, [event])
    assert not improvement.changed
    assert improvement.unresolved == (
        "encode_cmdline: insufficient evidence, no unchanged field can replace CommandLine "
        "in 'selection'",
    )


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
    assert improvement.new_rule.condition == (
        "(selection or yagtha_selection) and not filter_explorer"
    )
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
    assert improvement.new_rule.raw["detection"]["yagtha_selection"] == {
        "Image|endswith": "\\mimikatz.exe"
    }
    moved = get_mutation("change_path").apply(event)
    assert moved is not None
    assert matches(improvement.new_rule, moved)
    assert improvement.unresolved == (
        "rename_image: insufficient evidence, no unchanged field can replace Image in 'selection'",
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
    assert "Insufficient evidence" in improvement.rationale
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
  yagtha_selection:
    User: 'nobody'
  condition: selection or yagtha_selection
"""
    )
    analysis = analyze(rule, [mimikatz_event], ["rename_image"])
    improvement = improve(rule, analysis, [mimikatz_event])
    assert improvement.new_rule.condition == (
        "(selection or yagtha_selection_2) or yagtha_selection"
    )
    assert improvement.new_rule.selections["yagtha_selection"].fields == ("User",)


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


def test_render_condition() -> None:
    names = ["sel_a", "sel_b", "filter_x"]
    cases = {
        "sel_a": "(sel_a or y_a)",
        "sel_a and not filter_x": "(sel_a or y_a) and not filter_x",
        "1 of sel_* and not filter_x": "((sel_a or y_a) or sel_b) and not filter_x",
        "all of sel_*": "((sel_a or y_a) and sel_b)",
        "not (sel_b or filter_x) or sel_a": "not (sel_b or filter_x) or (sel_a or y_a)",
        "1 of filter_*": "filter_x",
    }
    for text, expected in cases.items():
        assert render_condition(parse_condition(text, names), {"sel_a": "y_a"}) == expected
