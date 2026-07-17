"""Command-line entry point.

Commands:

* ``yagtha analyze --rule RULE [--events EVENTS] [--mutations a,b] [--json]``
* ``yagtha list-mutations``

``improve`` and ``run`` arrive in later phases.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from yagtha import __version__
from yagtha.analyzer import analyze
from yagtha.errors import YagthaError
from yagtha.events import load_events
from yagtha.models import Analysis
from yagtha.mutations import list_mutations
from yagtha.rule_loader import load_rule

EXIT_OK = 0
EXIT_ERROR = 2


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

    commands.add_parser("list-mutations", help="list the available mutations")
    return parser


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    """Run the CLI and return the process exit code."""
    stream = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-mutations":
            _print_mutations(stream)
        else:
            _run_analyze(args, stream)
    except YagthaError as exc:
        print(f"yagtha: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def default_events_path(rule_path: Path) -> Path:
    """Built-in baseline events for a sample rule: ``../malicious_events/<stem>.json``."""
    return rule_path.resolve().parent.parent / "malicious_events" / f"{rule_path.stem}.json"


def _run_analyze(args: argparse.Namespace, stream: TextIO) -> None:
    rule = load_rule(args.rule)
    events = load_events(args.events or default_events_path(args.rule))
    names = None
    if args.mutations:
        names = [name.strip() for name in args.mutations.split(",") if name.strip()]
    analysis = analyze(rule, events, names)
    if args.json:
        json.dump(analysis_to_dict(analysis), stream, indent=2)
        stream.write("\n")
    else:
        stream.write(format_analysis(analysis))


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
