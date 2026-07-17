"""Tests for the analyzer: which variants evade, why, and how sure we are."""

from __future__ import annotations

from typing import Any

from yagtha.analyzer import analyze, remaining_signals
from yagtha.models import Confidence, Rule
from yagtha.rule_loader import parse_rule

POWERSHELL_EVENT: dict[str, Any] = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "OriginalFileName": "PowerShell.EXE",
    "CommandLine": 'powershell.exe -NoProfile -Command "Write-Output yagtha"',
    "ParentImage": "C:\\Windows\\explorer.exe",
}


def make_rule(detection: str) -> Rule:
    return parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\n"
        "detection:\n" + detection
    )


def test_mimikatz_rename_is_a_confirmed_evasion(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    analysis = analyze(mimikatz_rule, [mimikatz_event])
    assert analysis.undetected_baselines == ()
    assert [o.result.variant.mutation_name for o in analysis.evaded] == ["rename_image"]
    assert len(analysis.variants) == 4
    (finding,) = analysis.findings
    assert finding.mutation_name == "rename_image"
    assert finding.condition == "selection"
    assert finding.field == "Image"
    assert finding.confidence is Confidence.CONFIRMED
    assert "Image|endswith '\\mimikatz.exe' no longer matches" in finding.reason
    assert "update.exe" in finding.reason
    assert finding.remaining_signals == ("OriginalFileName", "CommandLine")


def test_selected_mutations_only(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    analysis = analyze(mimikatz_rule, [mimikatz_event], ["change_case"])
    assert [o.result.variant.mutation_name for o in analysis.variants] == ["change_case"]
    assert analysis.findings == ()


def test_undetected_baseline_produces_no_findings(mimikatz_rule: Rule) -> None:
    benign = {"Image": "C:\\Windows\\notepad.exe", "OriginalFileName": "NOTEPAD.EXE"}
    analysis = analyze(mimikatz_rule, [benign])
    assert analysis.undetected_baselines == (0,)
    assert analysis.findings == ()
    assert analysis.evaded == ()


def test_event_index_is_tracked(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    benign = {"Image": "C:\\Windows\\notepad.exe"}
    analysis = analyze(mimikatz_rule, [benign, mimikatz_event])
    assert analysis.undetected_baselines == (0,)
    assert {f.event_index for f in analysis.findings} == {1}


def test_encoded_command_evades_command_line_rule() -> None:
    rule = make_rule("  sel:\n    CommandLine|contains: Write-Output\n  condition: sel\n")
    analysis = analyze(rule, [POWERSHELL_EVENT])
    evaded = {o.result.variant.mutation_name for o in analysis.evaded}
    assert evaded == {"encode_cmdline"}
    (finding,) = analysis.findings
    assert finding.field == "CommandLine"
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.remaining_signals == ("OriginalFileName", "Image")


def test_two_changed_fields_give_likely_confidence() -> None:
    rule = make_rule(
        "  sel:\n"
        "    Image|endswith: '\\powershell.exe'\n"
        "    CommandLine|startswith: 'powershell.exe -NoProfile'\n"
        "  condition: sel\n"
    )
    analysis = analyze(rule, [POWERSHELL_EVENT], ["rename_image"])
    fields = {f.field: f.confidence for f in analysis.findings}
    assert fields == {"Image": Confidence.LIKELY, "CommandLine": Confidence.LIKELY}


def test_filter_that_starts_matching_is_reported(mimikatz_event: dict[str, Any]) -> None:
    rule = make_rule(
        "  selection:\n"
        "    OriginalFileName: mimikatz.exe\n"
        "  filter_explorer:\n"
        "    ParentImage|endswith: '\\explorer.exe'\n"
        "  condition: selection and not filter_explorer\n"
    )
    analysis = analyze(rule, [mimikatz_event])
    (finding,) = analysis.findings
    assert finding.mutation_name == "alt_parent"
    assert finding.condition == "filter_explorer"
    assert finding.field == "ParentImage"
    assert finding.reason.startswith("filter 'filter_explorer' now matches ParentImage")
    assert finding.confidence is Confidence.CONFIRMED


def test_remaining_signals_compare_arguments_and_ignore_case() -> None:
    before = {
        "OriginalFileName": "mimikatz.exe",
        "CommandLine": "mimikatz.exe a b",
        "Hashes": "SHA256=AA",
    }
    after = {
        "OriginalFileName": "MIMIKATZ.EXE",
        "CommandLine": "update.exe A B",
        "Hashes": "SHA256=BB",
    }
    assert remaining_signals(before, after) == ("OriginalFileName", "CommandLine")
    assert remaining_signals(before, after, exclude=["CommandLine"]) == ("OriginalFileName",)
    assert remaining_signals({"CommandLine": "x.exe"}, {"CommandLine": "y.exe"}) == ()
