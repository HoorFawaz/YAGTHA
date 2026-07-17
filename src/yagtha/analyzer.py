"""Run a rule on mutated variants and explain every evasion.

For each baseline event the rule should catch, the analyzer builds the
variants, evaluates the rule on each one and, for every variant that
slips through, reports:

* which mutation caused the miss;
* which selection and field stopped matching, and how;
* the confidence: ``confirmed`` when putting the field's original value
  back makes the rule fire again (the cause is reproduced), ``likely``
  when the miss needs more than that one field to explain it;
* which fields in the variant still carry the malicious signal.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from yagtha.evaluator import evaluate, match_selection, matches
from yagtha.models import (
    Analysis,
    Confidence,
    EvalResult,
    Event,
    FieldCondition,
    Finding,
    Outcome,
    Rule,
    Selection,
)
from yagtha.mutations import MAX_VARIANTS, generate_variants
from yagtha.mutations.cmdline import split_args

# Fields that identify what actually ran, most robust first.
SIGNAL_FIELDS = (
    "OriginalFileName",
    "Hashes",
    "Imphash",
    "CommandLine",
    "Description",
    "Product",
    "Company",
    "Image",
)
MAX_SHOWN_VALUES = 3


def analyze(
    rule: Rule,
    events: Sequence[Event],
    mutation_names: Iterable[str] | None = None,
    max_variants: int = MAX_VARIANTS,
) -> Analysis:
    """Evaluate ``rule`` on every baseline event and all of its variants."""
    names = None if mutation_names is None else tuple(mutation_names)
    outcomes: list[Outcome] = []
    findings: list[Finding] = []
    undetected: list[int] = []
    for index, event in enumerate(events):
        baseline, *variants = generate_variants(event, names, max_variants)
        baseline_result = evaluate(rule, baseline)
        outcomes.append(Outcome(event_index=index, result=baseline_result))
        if not baseline_result.matched:
            undetected.append(index)
        for variant in variants:
            result = evaluate(rule, variant)
            evaded = baseline_result.matched and not result.matched
            outcomes.append(Outcome(event_index=index, result=result, evaded=evaded))
            if evaded:
                findings.extend(explain_evasion(rule, event, result, index))
    return Analysis(
        rule=rule,
        outcomes=tuple(outcomes),
        findings=tuple(findings),
        undetected_baselines=tuple(undetected),
    )


def explain_evasion(rule: Rule, baseline: Event, result: EvalResult, index: int) -> list[Finding]:
    """Build one finding per field that made the variant evade the rule."""
    variant_event = result.variant.event
    failed = {f for fields in result.failed_fields.values() for f in fields}
    signals = remaining_signals(baseline, variant_event, exclude=failed)
    findings: list[Finding] = []
    for condition in result.failed_conditions:
        selection = rule.selections[condition]
        for field_name in result.failed_fields.get(condition, ()):
            findings.append(
                Finding(
                    mutation_name=result.variant.mutation_name,
                    field=field_name,
                    reason=_reason(selection, field_name, baseline, variant_event),
                    confidence=_confidence(rule, variant_event, baseline, field_name),
                    condition=condition,
                    remaining_signals=signals,
                    event_index=index,
                )
            )
    return findings


def remaining_signals(
    baseline: Event, variant: Event, exclude: Iterable[str] = ()
) -> tuple[str, ...]:
    """Fields that still show the same behaviour in the variant as in the baseline.

    Values are compared case-insensitively; for ``CommandLine`` only the
    arguments are compared, because renaming the executable changes the
    first token but not what the process was asked to do.
    """
    excluded = set(exclude)
    signals: list[str] = []
    for field_name in SIGNAL_FIELDS:
        if field_name in excluded:
            continue
        before, after = baseline.get(field_name), variant.get(field_name)
        if not isinstance(before, str) or not isinstance(after, str) or not after:
            continue
        if field_name == "CommandLine":
            same = _arguments(before) == _arguments(after) and bool(_arguments(after))
        else:
            same = before.casefold() == after.casefold()
        if same:
            signals.append(field_name)
    return tuple(signals)


def _arguments(command_line: str) -> list[str]:
    """Command-line arguments after the executable, casefolded."""
    return [token.casefold() for token in split_args(command_line)[1:]]


def _confidence(rule: Rule, variant: Event, baseline: Event, field_name: str) -> Confidence:
    """Confirm the cause by restoring the field's baseline value and re-evaluating."""
    restored = dict(variant)
    if field_name in baseline:
        restored[field_name] = baseline[field_name]
    else:
        restored.pop(field_name, None)
    return Confidence.CONFIRMED if matches(rule, restored) else Confidence.LIKELY


def _reason(selection: Selection, field_name: str, baseline: Event, variant: Event) -> str:
    """Explain in one sentence how the field defeated the selection."""
    now = _show(variant.get(field_name))
    if match_selection(selection, variant):
        return (
            f"filter '{selection.name}' now matches {field_name} = {now}, "
            "which suppresses the alert"
        )
    description = _describe(selection, field_name)
    before = _show(baseline.get(field_name))
    if before == now:
        return f"{description} does not match {field_name} = {now}"
    return f"{description} no longer matches: {field_name} changed from {before} to {now}"


def _describe(selection: Selection, field_name: str) -> str:
    """Render the rule's condition on ``field_name``, e.g. ``Image|endswith '\\a.exe'``."""
    for alternative in selection.alternatives:
        for condition in alternative:
            if condition.field == field_name:
                return _render(condition)
    return field_name


def _render(condition: FieldCondition) -> str:
    """Format a field condition like it appears in the rule."""
    key = "|".join([condition.field, *(m.value for m in condition.modifiers)])
    shown = [_show(value) for value in condition.values[:MAX_SHOWN_VALUES]]
    if len(condition.values) > MAX_SHOWN_VALUES:
        shown.append("...")
    return f"{key} {', '.join(shown)}"


def _show(value: object) -> str:
    """Quote a value for a message, or say it is missing."""
    if value is None:
        return "(missing)"
    return f"'{value}'"
