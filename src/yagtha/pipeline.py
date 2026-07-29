"""The full YAGTHA pipeline as plain functions, shared by the CLI and the web UI.

``run_pipeline`` analyses, improves and verifies one rule; ``bundle_files``
turns the result into the files of an export bundle (text only, nothing is
written here).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from yagtha import exporter
from yagtha.analyzer import analyze
from yagtha.improver import improve
from yagtha.models import Event, Improvement, RegressionCase, Rule, Verification
from yagtha.reporter import Verdict, render_report, verdict
from yagtha.rule_loader import parse_rule
from yagtha.verifier import build_regression_cases, cases_to_dict, verify


@dataclass(frozen=True)
class RunResult:
    """Everything one run of the pipeline produced."""

    rule_text: str
    rule: Rule
    improvement: Improvement
    verification: Verification
    cases: tuple[RegressionCase, ...]

    @property
    def verdict(self) -> Verdict:
        return verdict(self.improvement, self.verification)


def run_pipeline(
    rule_text: str,
    events: Sequence[Event],
    benign: Sequence[Event],
    mutation_names: Iterable[str] | None = None,
) -> RunResult:
    """Parse the rule, then analyse, improve and verify it."""
    return run_rule(parse_rule(rule_text), rule_text, events, benign, mutation_names)


def run_rule(
    rule: Rule,
    rule_text: str,
    events: Sequence[Event],
    benign: Sequence[Event],
    mutation_names: Iterable[str] | None = None,
) -> RunResult:
    """Analyse, improve and verify an already parsed rule."""
    names = None if mutation_names is None else tuple(mutation_names)
    analysis = analyze(rule, events, names)
    improvement = improve(rule, analysis, events)
    verification = verify(rule, improvement.new_rule, events, benign, names)
    cases = build_regression_cases(verification, benign) if improvement.changed else ()
    return RunResult(rule_text, rule, improvement, verification, cases)


def bundle_files(result: RunResult, ai_summary: str | None = None) -> dict[str, str]:
    """File name -> content for the export bundle, in ``exporter.BUNDLE_FILES`` order."""
    improvement, verification, cases = result.improvement, result.verification, result.cases
    files = {
        exporter.ORIGINAL_RULE: result.rule_text,
        exporter.ANALYSIS: json.dumps(
            improvement_to_dict(improvement, verification, cases), indent=2
        )
        + "\n",
    }
    if improvement.changed:
        files[exporter.IMPROVED_RULE] = improvement.yaml_text
        files[exporter.REGRESSION_CASES] = (
            json.dumps(cases_to_dict(improvement.new_rule, cases), indent=2) + "\n"
        )
        files[exporter.REGRESSION_TEST] = exporter.REGRESSION_TEST_SOURCE
    names = [name for name in exporter.BUNDLE_FILES if name in files or name == exporter.REPORT]
    files[exporter.REPORT] = render_report(improvement, verification, cases, names, ai_summary)
    return {name: files[name] for name in names}


def improvement_to_dict(
    improvement: Improvement, verification: Verification, cases: Sequence[RegressionCase]
) -> dict[str, Any]:
    """JSON-friendly view of an improvement and its verification."""
    return {
        "rule": {"id": verification.original.rule.id, "title": verification.original.rule.title},
        "changed": improvement.changed,
        "changes": list(improvement.changes),
        "unresolved": list(improvement.unresolved),
        "rationale": improvement.rationale,
        "improved_rule": {
            "id": improvement.new_rule.id,
            "title": improvement.new_rule.title,
            "yaml": improvement.yaml_text,
        },
        "verification": {
            "passed": verification.passed,
            "evaded_before": len(verification.original.evaded),
            "evaded_after": len(verification.improved.evaded),
            "fixed": list(verification.fixed),
            "regressions": list(verification.regressions),
            "benign_total": verification.benign_total,
            "benign_hits_original": list(verification.benign_hits_original),
            "benign_hits_improved": list(verification.benign_hits_improved),
            "new_false_positives": list(verification.new_false_positives),
        },
        "regression_cases": len(cases),
    }
