"""Tests for the Markdown report."""

from __future__ import annotations

from typing import Any

from yagtha.analyzer import analyze
from yagtha.improver import improve
from yagtha.models import Event, Rule
from yagtha.reporter import Verdict, render_report, verdict
from yagtha.rule_loader import parse_rule
from yagtha.verifier import build_regression_cases, verify


def run(
    rule: Rule, events: list[Any], benign: list[Any], names: list[str] | None = None
) -> tuple[Verdict, str]:
    analysis = analyze(rule, events, names)
    improvement = improve(rule, analysis, events)
    verification = verify(rule, improvement.new_rule, events, benign, names)
    cases = build_regression_cases(verification, benign) if improvement.changed else ()
    return verdict(improvement, verification), render_report(
        improvement, verification, cases, ["report.md"]
    )


def test_passed_report(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    result, text = run(mimikatz_rule, [mimikatz_event], [])
    assert result is Verdict.PASSED
    assert text.startswith("# YAGTHA report: Mimikatz Execution by Image Name\n")
    assert "**Verdict: PASSED.**" in text
    assert "| Variants evading | 1 of 4 | 0 of 4 |" in text
    assert "| 0 | `rename_image` | **missed** | caught |" in text
    assert "- Fixed: `event0/rename_image`" in text
    assert "```yaml\ntitle: Mimikatz Execution by Image Name (improved by YAGTHA)" in text
    assert "- `report.md`" in text


def test_report_is_deterministic(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    assert run(mimikatz_rule, [mimikatz_event], []) == run(mimikatz_rule, [mimikatz_event], [])


def test_robust_verdict(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> None:
    result, text = run(mimikatz_rule, [mimikatz_event], [], ["change_case"])
    assert result is Verdict.ROBUST
    assert "No variant evaded the rule." in text
    assert "## Improved rule" not in text
    assert "| 0 | `change_case` | caught |" in text


def test_insufficient_evidence_verdict(mimikatz_rule: Rule) -> None:
    result, text = run(mimikatz_rule, [{"Image": "C:\\Tools\\mimikatz.exe"}], [])
    assert result is Verdict.INSUFFICIENT_EVIDENCE
    assert "### Not fixed automatically" in text
    assert "insufficient evidence" in text
    assert "| Rule id | `6a1f3c52-2b7e-4d8a-9c41-0e5b7f2d9a13` | not changed |" in text


def test_not_detected_verdict(mimikatz_rule: Rule) -> None:
    result, text = run(mimikatz_rule, [{"Image": "C:\\Windows\\notepad.exe"}], [])
    assert result is Verdict.NOT_DETECTED
    assert "Baseline event 0 is not detected" in text


def test_failed_verdict_lists_false_positives(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    benign: list[Event] = [{"Image": "C:\\Tools\\other.exe", "OriginalFileName": "mimikatz.exe"}]
    result, text = run(mimikatz_rule, [mimikatz_event], benign)
    assert result is Verdict.FAILED
    assert "- New false positives on benign events: 0" in text


def test_untrusted_values_are_escaped() -> None:
    rule = parse_rule(
        "title: 'Evil | ```title``` <script>'\nlogsource:\n  category: process_creation\n"
        "  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\a.exe'\n"
        "  condition: selection\n"
    )
    event = {"Image": "C:\\x\\a.exe", "OriginalFileName": "a|b`c\n# heading"}
    _, text = run(rule, [event], [], ["rename_image"])
    assert text.startswith("# YAGTHA report: Evil \\| \\`\\`\\`title\\`\\`\\` \\<script\\>\n")
    before, _, rest = text.partition("\n````yaml\n")
    rule_yaml, _, after = rest.partition("\n````\n")
    assert "<script>" in rule_yaml
    assert "<script>" not in before + after
    assert "\n# heading" not in text
    assert "a\\|b\\`c \\# heading" in text
