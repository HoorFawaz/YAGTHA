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
    """Why one variant evaded the rule."""

    mutation_name: str
    field: str
    reason: str
    confidence: Confidence


@dataclass(frozen=True)
class Improvement:
    """A proposed, more robust rule and the reasoning behind it."""

    new_rule: Rule
    changes: tuple[str, ...]
    rationale: str
