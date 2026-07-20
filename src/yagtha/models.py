"""Data model shared by every YAGTHA component.

All classes are frozen dataclasses: once a rule or a result is built it never
changes, which keeps the pipeline easy to reason about and test.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeAlias

# A log event: Sysmon-like field names mapped to their values.
Event: TypeAlias = Mapping[str, Any]

# A literal value inside a rule. ``None`` means "field is missing or empty".
RuleValue: TypeAlias = str | int | float | bool | None


class Modifier(StrEnum):
    """Supported Sigma field modifiers."""

    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    ALL = "all"
    RE = "re"


@dataclass(frozen=True)
class FieldCondition:
    """One ``Field|modifier: value(s)`` entry of a selection.

    Values are combined with OR, or with AND when the ``all`` modifier is set.
    """

    field: str
    modifiers: tuple[Modifier, ...]
    values: tuple[RuleValue, ...]

    @property
    def match_all(self) -> bool:
        """True when every value must match (``all`` modifier)."""
        return Modifier.ALL in self.modifiers


@dataclass(frozen=True)
class Selection:
    """A named selection of the detection block.

    ``alternatives`` holds one tuple of field conditions per map. A selection
    written as a single map has one alternative; a list of maps has several,
    combined with OR. Conditions inside one alternative are combined with AND.
    """

    name: str
    alternatives: tuple[tuple[FieldCondition, ...], ...]

    @property
    def fields(self) -> tuple[str, ...]:
        """Field names used by this selection, in order, without duplicates."""
        seen: dict[str, None] = {}
        for alternative in self.alternatives:
            for condition in alternative:
                seen.setdefault(condition.field, None)
        return tuple(seen)


@dataclass(frozen=True)
class Rule:
    """A Sigma rule parsed into the internal model."""

    id: str
    title: str
    logsource: Mapping[str, str]
    selections: Mapping[str, Selection]
    condition: str
    level: str = "medium"
    description: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class Variant:
    """An event produced by a mutation (or the untouched baseline event)."""

    mutation_name: str
    event: Event


@dataclass(frozen=True)
class EvalResult:
    """Result of evaluating one rule on one variant.

    ``failed_conditions`` names the selections that caused the miss (empty when
    the rule matched). ``failed_fields`` maps each of those selections to the
    fields that did not match inside it.
    """

    rule_id: str
    variant: Variant
    matched: bool
    failed_conditions: tuple[str, ...] = ()
    failed_fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


class Confidence(StrEnum):
    """How sure the analyzer is about a finding."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"


@dataclass(frozen=True)
class Finding:
    """Why one variant evaded the rule.

    ``condition`` is the selection that stopped matching, ``remaining_signals``
    the fields that still carry the malicious behaviour in the variant, and
    ``event_index`` the baseline event the variant came from.
    """

    mutation_name: str
    field: str
    reason: str
    confidence: Confidence
    condition: str = ""
    remaining_signals: tuple[str, ...] = ()
    event_index: int = 0


@dataclass(frozen=True)
class Outcome:
    """One evaluated variant and the baseline event it came from.

    ``evaded`` is True only when the rule caught the baseline but missed
    this mutated variant.
    """

    event_index: int
    result: EvalResult
    evaded: bool = False


@dataclass(frozen=True)
class Analysis:
    """Result of running one rule against baseline events and their variants."""

    rule: Rule
    outcomes: tuple[Outcome, ...]
    findings: tuple[Finding, ...]
    undetected_baselines: tuple[int, ...] = ()

    @property
    def variants(self) -> tuple[Outcome, ...]:
        """Outcomes of mutated variants (baselines left out)."""
        return tuple(o for o in self.outcomes if o.result.variant.mutation_name != "original")

    @property
    def evaded(self) -> tuple[Outcome, ...]:
        """Mutated variants that evaded the rule."""
        return tuple(o for o in self.outcomes if o.evaded)


@dataclass(frozen=True)
class Improvement:
    """A proposed, more robust rule and the reasoning behind it.

    ``changes`` lists what was added, ``unresolved`` the evasions YAGTHA
    could not fix from the evidence in the events, and ``yaml_text`` the
    improved rule as Sigma YAML (empty when nothing changed).
    """

    new_rule: Rule
    changes: tuple[str, ...]
    rationale: str
    unresolved: tuple[str, ...] = ()
    yaml_text: str = ""

    @property
    def changed(self) -> bool:
        """True when a new rule was proposed."""
        return bool(self.changes)


class Expected(StrEnum):
    """What a regression case expects the rule to do."""

    MATCH = "match"
    NO_MATCH = "no_match"


@dataclass(frozen=True)
class RegressionCase:
    """One event and whether the rule must fire on it."""

    name: str
    expected: Expected
    event: Event


@dataclass(frozen=True)
class Verification:
    """Side-by-side test of the original and the improved rule.

    ``benign_hits_*`` are the indexes of benign events each rule fires on,
    ``regressions`` the malicious events or variants the original caught but
    the improved rule misses.
    """

    original: Analysis
    improved: Analysis
    benign_total: int
    benign_hits_original: tuple[int, ...]
    benign_hits_improved: tuple[int, ...]
    regressions: tuple[str, ...]

    @property
    def new_false_positives(self) -> tuple[int, ...]:
        """Benign events only the improved rule fires on."""
        before = set(self.benign_hits_original)
        return tuple(i for i in self.benign_hits_improved if i not in before)

    @property
    def fixed(self) -> tuple[str, ...]:
        """Evasions of the original rule that the improved rule catches."""
        still = {_key(o) for o in self.improved.evaded}
        return tuple(_key(o) for o in self.original.evaded if _key(o) not in still)

    @property
    def passed(self) -> bool:
        """No regression and no new false positive."""
        return not self.regressions and not self.new_false_positives


def _key(outcome: Outcome) -> str:
    """Stable label of a variant: ``event<index>/<mutation>``."""
    return f"event{outcome.event_index}/{outcome.result.variant.mutation_name}"
