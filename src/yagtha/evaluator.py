"""Decide whether a rule matches an event (own minimal Sigma implementation).

Matching follows Sigma semantics for the supported subset:

* string comparison is case-insensitive, ``*`` and ``?`` are wildcards and
  ``\\*``, ``\\?``, ``\\\\`` escape them;
* ``contains`` / ``startswith`` / ``endswith`` wrap the value in wildcards;
* ``re`` is a case-sensitive regex search with a time limit;
* a ``null`` value matches a missing or empty field.

Wildcards are matched with a linear-backtracking algorithm, never converted
to a regex, so a rule cannot trigger catastrophic backtracking through them.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from functools import lru_cache
from typing import Any

import regex

from yagtha.condition import Node, evaluate_condition, explain_condition, parse_condition
from yagtha.errors import RuleEvaluationError
from yagtha.models import (
    EvalResult,
    Event,
    FieldCondition,
    Modifier,
    Rule,
    RuleValue,
    Selection,
    Variant,
)

MAX_EVENT_VALUE_LENGTH = 32_768
REGEX_TIMEOUT_SECONDS = 0.25


class _Wild(Enum):
    """Wildcard tokens of a compiled Sigma value."""

    ANY = "*"
    ONE = "?"


_Token = str | _Wild


def evaluate(rule: Rule, variant: Variant) -> EvalResult:
    """Evaluate ``rule`` on one variant and explain a miss."""
    results = {name: match_selection(sel, variant.event) for name, sel in rule.selections.items()}
    tree = _parsed_condition(rule.condition, tuple(rule.selections))
    if evaluate_condition(tree, results):
        return EvalResult(rule_id=rule.id, variant=variant, matched=True)
    failed = explain_condition(tree, results)
    failed_fields = {
        name: _responsible_fields(rule.selections[name], variant.event, results[name])
        for name in failed
    }
    return EvalResult(
        rule_id=rule.id,
        variant=variant,
        matched=False,
        failed_conditions=failed,
        failed_fields=failed_fields,
    )


def matches(rule: Rule, event: Event) -> bool:
    """Return True when ``rule`` fires on ``event``."""
    return evaluate(rule, Variant(mutation_name="original", event=event)).matched


def match_selection(selection: Selection, event: Event) -> bool:
    """Return True when any alternative map of the selection matches."""
    return any(
        all(match_field(condition, event) for condition in alternative)
        for alternative in selection.alternatives
    )


def match_field(condition: FieldCondition, event: Event) -> bool:
    """Return True when the event field satisfies the condition's values."""
    checks = (
        _match_value(condition, value, event.get(condition.field)) for value in condition.values
    )
    return all(checks) if condition.match_all else any(checks)


def _responsible_fields(selection: Selection, event: Event, matched: bool) -> tuple[str, ...]:
    """Fields that explain the selection's result.

    For a selection that did not match: the fields that failed. For a matching
    selection (a negated filter that blocked the rule): the fields that matched.
    """
    fields: dict[str, None] = {}
    for alternative in selection.alternatives:
        outcomes = [(c.field, match_field(c, event)) for c in alternative]
        if matched and not all(ok for _, ok in outcomes):
            continue
        for field_name, ok in outcomes:
            if ok == matched:
                fields.setdefault(field_name, None)
    return tuple(fields)


def _match_value(condition: FieldCondition, expected: RuleValue, actual: Any) -> bool:
    """Compare one rule value with the event's field value."""
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    text = _to_text(actual)
    if len(text) > MAX_EVENT_VALUE_LENGTH:
        raise RuleEvaluationError(
            f"event field '{condition.field}' is longer than {MAX_EVENT_VALUE_LENGTH} characters"
        )
    if Modifier.RE in condition.modifiers:
        return _regex_search(str(expected), text, condition.field)
    if not isinstance(expected, str):
        return text.casefold() == _to_text(expected).casefold()
    return _glob_match(_compile_value(expected, _mode(condition.modifiers)), text.casefold())


def _mode(modifiers: Sequence[Modifier]) -> str:
    """Return the string-matching mode set by the modifiers."""
    for modifier in (Modifier.CONTAINS, Modifier.STARTSWITH, Modifier.ENDSWITH):
        if modifier in modifiers:
            return modifier.value
    return "exact"


def _to_text(value: Any) -> str:
    """Render an event or rule value the way Sigma compares it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _regex_search(pattern: str, text: str, field_name: str) -> bool:
    """Run a time-limited regex search."""
    try:
        return regex.search(pattern, text, timeout=REGEX_TIMEOUT_SECONDS) is not None
    except TimeoutError:
        raise RuleEvaluationError(
            f"regex on field '{field_name}' took longer than {REGEX_TIMEOUT_SECONDS}s"
        ) from None


@lru_cache(maxsize=4096)
def _compile_value(value: str, mode: str) -> tuple[_Token, ...]:
    """Turn a Sigma string value into casefolded literal and wildcard tokens."""
    tokens: list[_Token] = []
    literal: list[str] = []

    def flush() -> None:
        tokens.extend("".join(literal).casefold())
        literal.clear()

    index = 0
    while index < len(value):
        char = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if char == "\\" and following in {"*", "?", "\\"}:
            literal.append(following)
            index += 2
            continue
        if char in {"*", "?"}:
            flush()
            tokens.append(_Wild.ANY if char == "*" else _Wild.ONE)
        else:
            literal.append(char)
        index += 1
    flush()
    if mode in {"contains", "endswith"}:
        tokens.insert(0, _Wild.ANY)
    if mode in {"contains", "startswith"}:
        tokens.append(_Wild.ANY)
    return tuple(tokens)


def _glob_match(tokens: tuple[_Token, ...], text: str) -> bool:
    """Wildcard match in O(len(tokens) * len(text)) time, without recursion."""
    t_index = p_index = 0
    star_index, star_text = -1, 0
    while t_index < len(text):
        token = tokens[p_index] if p_index < len(tokens) else None
        if token is _Wild.ONE or (isinstance(token, str) and token == text[t_index]):
            p_index += 1
            t_index += 1
        elif token is _Wild.ANY:
            star_index, star_text = p_index, t_index
            p_index += 1
        elif star_index >= 0:
            star_text += 1
            p_index, t_index = star_index + 1, star_text
        else:
            return False
    while p_index < len(tokens) and tokens[p_index] is _Wild.ANY:
        p_index += 1
    return p_index == len(tokens)


@lru_cache(maxsize=256)
def _parsed_condition(condition: str, names: tuple[str, ...]) -> Node:
    """Parse a condition once per rule shape."""
    return parse_condition(condition, names)
