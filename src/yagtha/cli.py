"""Command-line entry point.

Commands:

* ``yagtha analyze --rule RULE [--events EVENTS] [--mutations a,b] [--json]``
* ``yagtha improve --rule RULE [--events EVENTS] [--benign BENIGN] [--mutations a,b] [--json]``
* ``yagtha run --rule RULE_OR_FOLDER [--events EVENTS] [--benign BENIGN] [--mutations a,b]
  [--out output/]``
* ``yagtha list-mutations``

``run`` does analysis, improvement and verification in one go and exports the
bundle (rules, regression tests, report) to ``output/<rule name>/``. Given a
folder, it runs every ``*.yml`` rule in it. It exits with 1 when an improved
rule fails verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from yagtha import __version__, exporter
from yagtha.analyzer import analyze
from yagtha.errors import YagthaError
from yagtha.events import EventDict, load_events
from yagtha.improver import improve
from yagtha.models import Analysis, Improvement, RegressionCase, Rule, Verification
from yagtha.mutations import list_mutations
from yagtha.reporter import Verdict, render_report, verdict
from yagtha.rule_loader import load_rule, parse_rule, read_rule_text
from yagtha.verifier import build_regression_cases, cases_to_dict, verify

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
MAX_RULES_PER_RUN = 100


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="yagtha",
        description="Test how robust Sigma detection rules are against attacker variations.",
    )
    parser.add_argument("--version", action="version", version=f"yagtha {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = commands.add_parser("analyze", help="find which variations evade a rule")
    analyze_cmd.add_argument("--rule", required=True, type=Path, help="Sigma rule (YAML)")
    analyze_cmd.add_argument(
        "--events",
        type=Path,
        help="baseline events (JSON); default: data/malicious_events/<rule name>.json",
    )
    analyze_cmd.add_argument("--mutations", help="comma-separated mutation names (default: all)")
    analyze_cmd.add_argument("--json", action="store_true", help="print the result as JSON")

    improve_cmd = commands.add_parser(
        "improve", help="propose a more robust rule and verify it on benign events"
    )
    _add_pipeline_arguments(improve_cmd)
    improve_cmd.add_argument("--json", action="store_true", help="print the result as JSON")

    run_cmd = commands.add_parser(
        "run", help="analyze, improve, verify and export the bundle with the report"
    )
    _add_pipeline_arguments(run_cmd)
    run_cmd.add_argument(
        "--out",
        type=Path,
        default=exporter.DEFAULT_ROOT,
        help="output folder, must be inside ./output (default: output/)",
    )

    commands.add_parser("list-mutations", help="list the available mutations")
    return parser


def _add_pipeline_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--rule", required=True, type=Path, help="Sigma rule (YAML), or a folder of rules for run"
    )
    command.add_argument(
        "--events",
        type=Path,
        help="baseline events (JSON); default: data/malicious_events/<rule name>.json",
    )
    command.add_argument(
        "--benign",
        type=Path,
        help="normal activity events (JSON); default: data/benign_events/benign.json",
    )
    command.add_argument("--mutations", help="comma-separated mutation names (default: all)")


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    """Run the CLI and return the process exit code."""
    stream = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-mutations":
            _print_mutations(stream)
        elif args.command == "improve":
            _run_improve(args, stream)
        elif args.command == "run":
            return _run_command(args, stream)
        else:
            _run_analyze(args, stream)
    except YagthaError as exc:
        print(f"yagtha: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def default_events_path(rule_path: Path) -> Path:
    """Built-in baseline events for a sample rule: ``../malicious_events/<stem>.json``."""
    return rule_path.resolve().parent.parent / "malicious_events" / f"{rule_path.stem}.json"


def default_benign_path(rule_path: Path) -> Path:
    """Built-in benign corpus next to the sample rules: ``../benign_events/benign.json``."""
    return rule_path.resolve().parent.parent / "benign_events" / "benign.json"


def _mutation_names(args: argparse.Namespace) -> list[str] | None:
    if not args.mutations:
        return None
    return [name.strip() for name in args.mutations.split(",") if name.strip()]


def _run_analyze(args: argparse.Namespace, stream: TextIO) -> None:
    rule = load_rule(args.rule)
    events = load_events(args.events or default_events_path(args.rule))
    analysis = analyze(rule, events, _mutation_names(args))
    if args.json:
        json.dump(analysis_to_dict(analysis), stream, indent=2)
        stream.write("\n")
    else:
        stream.write(format_analysis(analysis))


def _load_benign(args: argparse.Namespace) -> list[EventDict]:
    benign_path = args.benign or default_benign_path(args.rule)
    if args.benign is None and not benign_path.is_file():
        print(
            "yagtha: warning: no benign events found, false positives are not checked",
            file=sys.stderr,
        )
        return []
    return load_events(benign_path)


def _improve_and_verify(
    args: argparse.Namespace, rule: Rule
) -> tuple[Improvement, Verification, tuple[RegressionCase, ...]]:
    events = load_events(args.events or default_events_path(args.rule))
    benign = _load_benign(args)
    names = _mutation_names(args)
    analysis = analyze(rule, events, names)
    improvement = improve(rule, analysis, events)
    verification = verify(rule, improvement.new_rule, events, benign, names)
    cases = build_regression_cases(verification, benign) if improvement.changed else ()
    return improvement, verification, cases


def _run_improve(args: argparse.Namespace, stream: TextIO) -> None:
    improvement, verification, cases = _improve_and_verify(args, load_rule(args.rule))
    if args.json:
        json.dump(improvement_to_dict(improvement, verification, cases), stream, indent=2)
        stream.write("\n")
    else:
        stream.write(format_improvement(improvement, verification, cases))


def _run_command(args: argparse.Namespace, stream: TextIO) -> int:
    """``run`` on one rule file, or on every rule of a folder."""
    if not args.rule.is_dir():
        return _run_pipeline(args, stream)
    if args.events is not None:
        raise YagthaError("--events cannot be used with a folder of rules")
    rules = sorted(args.rule.glob("*.yml"))
    if not rules:
        raise YagthaError(f"no .yml rules found in {args.rule}")
    if len(rules) > MAX_RULES_PER_RUN:
        raise YagthaError(f"more than {MAX_RULES_PER_RUN} rules in {args.rule}")
    verdicts: list[str] = []
    code = EXIT_OK
    for path in rules:
        stream.write(f"== {path.name}\n")
        rule_args = argparse.Namespace(**{**vars(args), "rule": path})
        result = _run_pipeline(rule_args, stream, verdicts)
        code = max(code, result)
        stream.write("\n")
    counts = {name: verdicts.count(name) for name in dict.fromkeys(verdicts)}
    summary = ", ".join(f"{count} {name}" for name, count in counts.items())
    stream.write(f"Rules: {len(rules)} | {summary}\n")
    return code


def _run_pipeline(
    args: argparse.Namespace, stream: TextIO, verdicts: list[str] | None = None
) -> int:
    out = exporter.resolve_output_dir(args.out)
    rule_text = read_rule_text(args.rule)
    rule = parse_rule(rule_text)
    improvement, verification, cases = _improve_and_verify(args, rule)
    files = {
        exporter.ORIGINAL_RULE: rule_text,
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
    files[exporter.REPORT] = render_report(improvement, verification, cases, names)
    bundle = exporter.write_bundle(out, exporter.bundle_name(args.rule), files)
    result = verdict(improvement, verification)
    if verdicts is not None:
        verdicts.append(result.value)
    before, after = verification.original, verification.improved
    stream.write(f"Rule: {rule.title} ({rule.level})\n")
    stream.write(f"Variants evading: {len(before.evaded)} of {len(before.variants)}")
    if improvement.changed:
        stream.write(f" -> {len(after.evaded)} with the improved rule")
    stream.write("\n")
    stream.write(
        f"Benign events matched: {len(verification.benign_hits_original)}"
        + (f" -> {len(verification.benign_hits_improved)}" if improvement.changed else "")
        + f" (of {verification.benign_total})\n"
    )
    for note in improvement.unresolved:
        stream.write(f"Not fixed: {note}\n")
    stream.write(f"Verdict: {result.value}\n")
    stream.write(f"Bundle: {_display(bundle)}\n")
    for name in names:
        stream.write(f"  {name}\n")
    return EXIT_FAILED if result is Verdict.FAILED else EXIT_OK


def _display(path: Path) -> str:
    """Path relative to the current folder when possible, with forward slashes."""
    try:
        return path.relative_to(Path.cwd().resolve()).as_posix() + "/"
    except ValueError:
        return path.as_posix() + "/"


def format_improvement(
    improvement: Improvement, verification: Verification, cases: Sequence[RegressionCase]
) -> str:
    """Human-readable improvement and verification summary."""
    before, after = verification.original, verification.improved
    lines = [
        f"Rule: {before.rule.title} ({before.rule.level})",
        f"Original rule: {len(before.evaded)} of {len(before.variants)} variants evade it",
        "",
    ]
    if not improvement.changed:
        lines.append(improvement.rationale)
    else:
        lines.append("Proposed changes:")
        lines.extend(f"  - {change}" for change in improvement.changes)
    if improvement.unresolved:
        lines.append("")
        lines.append("Not fixed automatically:")
        lines.extend(f"  - {note}" for note in improvement.unresolved)
    if not improvement.changed:
        return "\n".join(lines) + "\n"
    lines += ["", "Improved rule:", "", improvement.yaml_text.rstrip(), "", "Verification:"]
    lines.append(f"  variants evading: {len(before.evaded)} -> {len(after.evaded)}")
    for key in verification.fixed:
        lines.append(f"    fixed      {key}")
    for outcome in after.evaded:
        lines.append(
            f"    still evades event{outcome.event_index}/{outcome.result.variant.mutation_name}"
        )
    lines.append(f"  regressions: {', '.join(verification.regressions) or 'none'}")
    lines.append(
        f"  benign events matched: {len(verification.benign_hits_original)} -> "
        f"{len(verification.benign_hits_improved)} (of {verification.benign_total})"
    )
    for index in verification.new_false_positives:
        lines.append(f"    new false positive: benign event {index}")
    matching = sum(1 for case in cases if case.expected.value == "match")
    lines.append(
        f"  regression cases: {len(cases)} ({matching} match, {len(cases) - matching} no_match)"
    )
    lines.append("")
    lines.append(f"Result: {'PASSED' if verification.passed else 'FAILED'}")
    return "\n".join(lines) + "\n"


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


def _print_mutations(stream: TextIO) -> None:
    mutations = list_mutations()
    width = max(len(m.name) for m in mutations)
    for mutation in mutations:
        stream.write(f"{mutation.name.ljust(width)}  {mutation.description}\n")


def format_analysis(analysis: Analysis) -> str:
    """Human-readable analysis summary."""
    rule = analysis.rule
    variants = analysis.variants
    evaded = analysis.evaded
    baselines = len(analysis.outcomes) - len(variants)
    lines = [
        f"Rule: {rule.title} ({rule.level})",
        f"Baseline events: {baselines} ({baselines - len(analysis.undetected_baselines)} detected)",
        f"Variants tested: {len(variants)} | caught: {len(variants) - len(evaded)} "
        f"| evaded: {len(evaded)}",
    ]
    for index in analysis.undetected_baselines:
        lines.append(
            f"WARNING: the rule does not detect baseline event {index}; "
            "its variants are not analysed."
        )
    lines.append("")
    for outcome in variants:
        name = outcome.result.variant.mutation_name
        if not outcome.evaded:
            if outcome.event_index not in analysis.undetected_baselines:
                lines.append(f"  caught   {name}")
            continue
        lines.append(f"  EVADED   {name}")
        for finding in analysis.findings:
            if finding.mutation_name != name or finding.event_index != outcome.event_index:
                continue
            lines.append(
                f"           [{finding.confidence.value}] {finding.condition}: {finding.reason}"
            )
            signals = ", ".join(finding.remaining_signals) or "none found"
            lines.append(f"           still visible in: {signals}")
    if not evaded and variants:
        lines.append("")
        lines.append("No variant evaded the rule.")
    return "\n".join(lines) + "\n"


def analysis_to_dict(analysis: Analysis) -> dict[str, Any]:
    """JSON-friendly view of an analysis."""
    return {
        "rule": {
            "id": analysis.rule.id,
            "title": analysis.rule.title,
            "level": analysis.rule.level,
        },
        "undetected_baselines": list(analysis.undetected_baselines),
        "variants": [
            {
                "event_index": o.event_index,
                "mutation": o.result.variant.mutation_name,
                "matched": o.result.matched,
                "evaded": o.evaded,
            }
            for o in analysis.variants
        ],
        "findings": [
            {
                "event_index": f.event_index,
                "mutation": f.mutation_name,
                "condition": f.condition,
                "field": f.field,
                "reason": f.reason,
                "confidence": f.confidence.value,
                "remaining_signals": list(f.remaining_signals),
            }
            for f in analysis.findings
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
