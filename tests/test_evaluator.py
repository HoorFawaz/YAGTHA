"""Tests for the evaluator, starting with the mimikatz rule from the brief."""

from __future__ import annotations

from typing import Any

import pytest

from yagtha.errors import RuleEvaluationError
from yagtha.evaluator import MAX_EVENT_VALUE_LENGTH, evaluate, matches
from yagtha.models import Rule, Variant
from yagtha.rule_loader import parse_rule


def make_rule(detection: str) -> Rule:
    """Build a rule from an indented detection block."""
    return parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\n"
        "detection:\n" + detection
    )


# --- The mimikatz rule ----------------------------------------------------


def test_mimikatz_rule_catches_baseline(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    result = evaluate(mimikatz_rule, Variant("original", mimikatz_event))
    assert result.matched
    assert result.rule_id == mimikatz_rule.id
    assert result.failed_conditions == ()


def test_mimikatz_rule_misses_renamed_binary(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    renamed = {**mimikatz_event, "Image": "C:\\Users\\analyst\\Downloads\\abc.exe"}
    result = evaluate(mimikatz_rule, Variant("rename_image", renamed))
    assert not result.matched
    assert result.failed_conditions == ("selection",)
    assert result.failed_fields == {"selection": ("Image",)}
    # The behaviour is still visible in fields the rule ignores.
    assert renamed["OriginalFileName"] == "mimikatz.exe"


def test_mimikatz_rule_is_case_insensitive(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    upper = {**mimikatz_event, "Image": "C:\\USERS\\ANALYST\\DOWNLOADS\\MiMiKaTz.EXE"}
    assert matches(mimikatz_rule, upper)


def test_mimikatz_rule_ignores_other_paths(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    # endswith '\mimikatz.exe' needs the backslash: notmimikatz.exe is another file.
    other = {**mimikatz_event, "Image": "C:\\Tools\\notmimikatz.exe"}
    assert not matches(mimikatz_rule, other)


def test_original_event_is_not_modified(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    before = dict(mimikatz_event)
    evaluate(mimikatz_rule, Variant("original", mimikatz_event))
    assert mimikatz_event == before


def test_benign_event_does_not_match(mimikatz_rule: Rule) -> None:
    benign = {
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "OriginalFileName": "NOTEPAD.EXE",
        "CommandLine": "notepad.exe C:\\Users\\analyst\\notes.txt",
    }
    assert not matches(mimikatz_rule, benign)


# --- Modifiers and wildcards ---------------------------------------------


@pytest.mark.parametrize(
    ("field_key", "value", "image", "expected"),
    [
        ("Image", "c:\\tools\\a.exe", "C:\\Tools\\A.EXE", True),
        ("Image", "c:\\tools\\a.exe", "C:\\Tools\\A.EXE.bak", False),
        ("Image|startswith", "C:\\Users\\", "C:\\Users\\x\\a.exe", True),
        ("Image|startswith", "C:\\Users\\", "D:\\Users\\a.exe", False),
        ("Image|contains", "\\Temp\\", "C:\\Windows\\TEMP\\a.exe", True),
        ("Image|contains", "\\Temp\\", "C:\\Windows\\a.exe", False),
        # In Sigma "\\*" is an escaped star, so a backslash before a wildcard is "\\\\*".
        ("Image", "*\\temp\\\\*.exe", "C:\\x\\Temp\\run.exe", True),
        ("Image", "*\\temp\\\\*.exe", "C:\\x\\Temp\\run.dll", False),
        ("Image", "?:\\a.exe", "C:\\a.exe", True),
        ("Image", "?:\\a.exe", "CC:\\a.exe", False),
        ("Image", "C:\\odd\\*name", "C:\\odd*name", True),
        ("Image", "C:\\odd\\*name", "C:\\oddXname", False),
        ("Image|re", "\\\\[a-z]{3}\\.exe$", "C:\\x\\abc.exe", True),
        ("Image|re", "\\\\[a-z]{3}\\.exe$", "C:\\x\\ABC.exe", False),
    ],
)
def test_string_matching(field_key: str, value: str, image: str, expected: bool) -> None:
    rule = parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\n"
        "detection:\n  sel:\n    " + field_key + ": " + _yaml_quote(value) + "\n  condition: sel\n"
    )
    assert matches(rule, {"Image": image}) is expected


def _yaml_quote(value: str) -> str:
    """Single-quote a value for YAML (backslashes stay literal)."""
    return "'" + value.replace("'", "''") + "'"


def test_escaped_wildcard_is_literal() -> None:
    rule = make_rule("  sel:\n    CommandLine|contains: '\\*'\n  condition: sel\n")
    assert matches(rule, {"CommandLine": "dir *.txt"})
    assert not matches(rule, {"CommandLine": "dir a.txt"})


def test_value_list_is_or_and_all_modifier_is_and() -> None:
    any_rule = make_rule("  sel:\n    CommandLine|contains: [-enc, -nop]\n  condition: sel\n")
    all_rule = make_rule("  sel:\n    CommandLine|contains|all: [-enc, -nop]\n  condition: sel\n")
    assert matches(any_rule, {"CommandLine": "powershell -enc AAA"})
    assert not matches(all_rule, {"CommandLine": "powershell -enc AAA"})
    assert matches(all_rule, {"CommandLine": "powershell -nop -enc AAA"})


def test_fields_in_one_map_are_and_and_maps_in_a_list_are_or() -> None:
    and_rule = make_rule("  sel:\n    Image: a.exe\n    User: bob\n  condition: sel\n")
    or_rule = make_rule("  sel:\n    - Image: a.exe\n    - User: bob\n  condition: sel\n")
    assert not matches(and_rule, {"Image": "a.exe", "User": "eve"})
    assert matches(or_rule, {"Image": "a.exe", "User": "eve"})


def test_null_matches_missing_or_empty_field() -> None:
    rule = make_rule("  sel:\n    OriginalFileName: null\n  condition: sel\n")
    assert matches(rule, {})
    assert matches(rule, {"OriginalFileName": ""})
    assert not matches(rule, {"OriginalFileName": "a.exe"})


def test_missing_field_does_not_match() -> None:
    rule = make_rule("  sel:\n    Image|contains: a\n  condition: sel\n")
    assert not matches(rule, {"CommandLine": "a"})


def test_numbers_and_booleans() -> None:
    rule = make_rule("  sel:\n    EventID: 1\n    Signed: false\n  condition: sel\n")
    assert matches(rule, {"EventID": 1, "Signed": False})
    assert matches(rule, {"EventID": "1", "Signed": "False"})
    assert not matches(rule, {"EventID": 10, "Signed": False})


def test_long_field_value_is_rejected() -> None:
    rule = make_rule("  sel:\n    CommandLine|contains: x\n  condition: sel\n")
    with pytest.raises(RuleEvaluationError, match="longer than"):
        matches(rule, {"CommandLine": "a" * (MAX_EVENT_VALUE_LENGTH + 1)})


def test_wildcard_matching_stays_fast_on_hostile_input() -> None:
    rule = make_rule("  sel:\n    CommandLine: '*a*a*a*a*a*a*a*a*b'\n  condition: sel\n")
    assert not matches(rule, {"CommandLine": "a" * 20_000})


# --- Conditions ----------------------------------------------------------

DETECTION = """\
  selection_img:
    Image|endswith: '\\mimikatz.exe'
  selection_ofn:
    OriginalFileName: mimikatz.exe
  filter_admin:
    User: LAB\\admin
"""


@pytest.mark.parametrize(
    ("condition", "event", "expected"),
    [
        ("selection_img or selection_ofn", {"OriginalFileName": "mimikatz.exe"}, True),
        ("selection_img and selection_ofn", {"OriginalFileName": "mimikatz.exe"}, False),
        ("1 of selection_*", {"OriginalFileName": "mimikatz.exe"}, True),
        ("all of selection_*", {"OriginalFileName": "mimikatz.exe"}, False),
        ("1 of them", {"User": "LAB\\admin"}, True),
        ("1 of selection_* and not filter_admin", {"Image": "x\\mimikatz.exe"}, True),
        (
            "1 of selection_* and not filter_admin",
            {"Image": "x\\mimikatz.exe", "User": "LAB\\admin"},
            False,
        ),
        ("not (selection_img or selection_ofn)", {}, True),
        ("selection_img or selection_ofn and filter_admin", {"Image": "x\\mimikatz.exe"}, True),
        ("(selection_img or selection_ofn) and filter_admin", {"Image": "x\\mimikatz.exe"}, False),
    ],
)
def test_condition_logic(condition: str, event: dict[str, str], expected: bool) -> None:
    rule = make_rule(DETECTION + f"  condition: {condition}\n")
    assert matches(rule, event) is expected


def test_them_skips_underscore_selections() -> None:
    rule = make_rule("  a:\n    Image: x\n  _helper:\n    Image: y\n  condition: all of them\n")
    assert matches(rule, {"Image": "x"})


def test_blame_names_the_filter_that_blocked_the_rule() -> None:
    rule = make_rule(DETECTION + "  condition: selection_img and not filter_admin\n")
    event = {"Image": "x\\mimikatz.exe", "User": "LAB\\admin"}
    result = evaluate(rule, Variant("alt_user", event))
    assert not result.matched
    assert result.failed_conditions == ("filter_admin",)
    assert result.failed_fields == {"filter_admin": ("User",)}


def test_blame_lists_every_failed_alternative() -> None:
    rule = make_rule(DETECTION + "  condition: 1 of selection_*\n")
    result = evaluate(rule, Variant("rename_image", {"Image": "x\\abc.exe"}))
    assert result.failed_conditions == ("selection_img", "selection_ofn")
    assert result.failed_fields == {
        "selection_img": ("Image",),
        "selection_ofn": ("OriginalFileName",),
    }


def test_blame_in_and_only_names_failed_parts() -> None:
    rule = make_rule(DETECTION + "  condition: selection_img and selection_ofn\n")
    result = evaluate(
        rule, Variant("rename_image", {"Image": "x\\abc.exe", "OriginalFileName": "mimikatz.exe"})
    )
    assert result.failed_conditions == ("selection_img",)
