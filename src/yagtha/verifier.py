"""Check that an improved rule is really better than the original.

The verifier runs both rules on the same malicious events and mutations,
and on a corpus of benign (normal activity) events, then reports:

* which evasions the improved rule fixes and which still evade;
* regressions: anything the original caught that the improved rule misses;
* false positives: benign events each rule fires on.

An improvement passes when it has no regression and no new false positive.
The verifier also turns the result into regression cases (event plus the
expected verdict) that can be saved and re-checked after every rule change.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from yagtha.analyzer import analyze
from yagtha.errors import EventValidationError
from yagtha.evaluator import matches
from yagtha.events import MAX_EVENTS_BYTES, validate_events
from yagtha.models import Event, Expected, RegressionCase, Rule, Verification
from yagtha.mutations import MAX_VARIANTS

MAX_CASES = 5_000


def verify(
    original: Rule,
    improved: Rule,
    events: Sequence[Event],
    benign: Sequence[Event],
    mutation_names: Iterable[str] | None = None,
    max_variants: int = MAX_VARIANTS,
) -> Verification:
    """Compare ``original`` and ``improved`` on malicious and benign events."""
    names = None if mutation_names is None else tuple(mutation_names)
    before = analyze(original, events, names, max_variants)
    after = analyze(improved, events, names, max_variants)
    regressions = []
    for old, new in zip(before.outcomes, after.outcomes, strict=True):
        if old.result.matched and not new.result.matched:
            mutation = old.result.variant.mutation_name
            regressions.append(f"event{old.event_index}/{mutation} is no longer detected")
    return Verification(
        original=before,
        improved=after,
        benign_total=len(benign),
        benign_hits_original=_hits(original, benign),
        benign_hits_improved=_hits(improved, benign),
        regressions=tuple(regressions),
    )


def _hits(rule: Rule, benign: Sequence[Event]) -> tuple[int, ...]:
    """Indexes of the benign events the rule fires on."""
    return tuple(i for i, event in enumerate(benign) if matches(rule, event))


def build_regression_cases(
    verification: Verification, benign: Sequence[Event]
) -> tuple[RegressionCase, ...]:
    """Lock in what the improved rule gets right.

    Every malicious event or variant it catches must keep matching, and every
    benign event it ignores must keep not matching. Cases the improved rule
    gets wrong are left out: they are reported by the verification instead.
    """
    cases: list[RegressionCase] = []
    for outcome in verification.improved.outcomes:
        if outcome.result.matched:
            variant = outcome.result.variant
            cases.append(
                RegressionCase(
                    name=f"event{outcome.event_index}-{variant.mutation_name}",
                    expected=Expected.MATCH,
                    event=variant.event,
                )
            )
    hits = set(verification.benign_hits_improved)
    for index, event in enumerate(benign):
        if index not in hits:
            cases.append(
                RegressionCase(name=f"benign{index}", expected=Expected.NO_MATCH, event=event)
            )
    return tuple(cases)


def check_cases(rule: Rule, cases: Iterable[RegressionCase]) -> list[str]:
    """Names of the cases the rule fails, with what went wrong."""
    failures = []
    for case in cases:
        fired = matches(rule, case.event)
        if fired != (case.expected is Expected.MATCH):
            verdict = "fired" if fired else "did not fire"
            failures.append(f"{case.name}: expected {case.expected.value} but the rule {verdict}")
    return failures


def cases_to_dict(rule: Rule, cases: Sequence[RegressionCase]) -> dict[str, Any]:
    """JSON-friendly regression file for ``rule``."""
    return {
        "rule_id": rule.id,
        "rule_title": rule.title,
        "cases": [
            {"name": c.name, "expected": c.expected.value, "event": dict(c.event)} for c in cases
        ],
    }


def cases_from_dict(data: Any) -> tuple[RegressionCase, ...]:
    """Validate a regression file read from JSON (untrusted input)."""
    if not isinstance(data, Mapping) or not isinstance(data.get("cases"), list):
        raise EventValidationError("regression file must be an object with a 'cases' list")
    items = data["cases"]
    if len(items) > MAX_CASES:
        raise EventValidationError(f"regression file has more than {MAX_CASES} cases")
    cases = []
    for position, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise EventValidationError(f"case {position} must be an object")
        name, expected = item.get("name"), item.get("expected")
        if not isinstance(name, str) or not name:
            raise EventValidationError(f"case {position} needs a non-empty 'name'")
        try:
            verdict = Expected(str(expected))
        except ValueError:
            raise EventValidationError(
                f"case {position}: 'expected' must be 'match' or 'no_match'"
            ) from None
        (event,) = validate_events([item.get("event")])
        cases.append(RegressionCase(name=name, expected=verdict, event=event))
    return tuple(cases)


def load_cases(path: str | Path) -> tuple[RegressionCase, ...]:
    """Read a regression file written by the exporter."""
    file_path = Path(path)
    try:
        if file_path.stat().st_size > MAX_EVENTS_BYTES:
            raise EventValidationError(
                f"regression file {file_path} is larger than {MAX_EVENTS_BYTES} bytes"
            )
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventValidationError(f"cannot read regression file {file_path}: {exc}") from exc
    return cases_from_dict(data)
