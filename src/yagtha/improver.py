"""Propose a more robust rule using only evidence found in the events.

The improver never invents values. Every value it adds is copied from a
baseline event the original rule already detects, and only from a field
the analyzer reported as still carrying the behaviour after a mutation.

Heuristics, applied to each evasion:

* the executable was renamed or moved but ``OriginalFileName`` (taken
  from the PE header) is unchanged: match on ``OriginalFileName``;
* the command-line arguments are unchanged: match on the significant
  arguments with ``CommandLine|contains|all`` (order and case free);
* only the folder of the executable changed: match on
  ``Image|endswith '\\<name>'``.

New selections are OR-ed with the original condition and keep every filter
(``not ...``) of the original rule, so a filter still suppresses them.
Evasions caused by a filter, or with no remaining signal, are reported as
unresolved instead of being guessed.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Sequence
from typing import Any

import yaml

from yagtha.condition import Node, Not, Of, Ref, parse_condition
from yagtha.evaluator import match_selection
from yagtha.models import Analysis, Event, Finding, Improvement, Rule
from yagtha.mutations.cmdline import basename, is_flag, split_args
from yagtha.rule_loader import parse_rule

PREFIX = "yagtha_"
MAX_TOKENS = 4
MIN_TOKEN_LENGTH = 4
MIN_PLAIN_TOKEN_LENGTH = 8
# Fixed namespace so the same improvement always gets the same rule id.
_ID_NAMESPACE = uuid.UUID("0f4c8a52-6d1e-4b7a-9e3f-2a5c7d9b1e60")

# key -> (selection maps, change description)
Proposals = dict[str, tuple[list[dict[str, Any]], str]]


def improve(rule: Rule, analysis: Analysis, events: Sequence[Event]) -> Improvement:
    """Build an improved rule from the analysis of ``rule`` on ``events``."""
    detected = [i for i in range(len(events)) if i not in analysis.undetected_baselines]
    proposals: Proposals = {}
    unresolved: list[str] = []
    for finding in analysis.findings:
        if _filter_suppressed(rule, analysis, finding):
            unresolved.append(
                f"{finding.mutation_name}: filter '{finding.condition}' suppresses the alert; "
                "filters are not changed automatically, review it by hand"
            )
        elif not _propose(finding, events, detected, proposals):
            unresolved.append(
                f"{finding.mutation_name}: no unchanged field shows the behaviour, "
                "so there is no safe value to match on"
            )
    if not proposals:
        rationale = (
            "No evasion found, the rule is unchanged."
            if not analysis.findings
            else "No automatic fix: no field in the events still shows the behaviour."
        )
        return Improvement(
            new_rule=rule, changes=(), rationale=rationale, unresolved=tuple(_unique(unresolved))
        )
    return _build(rule, proposals, _unique(unresolved))


def _filter_suppressed(rule: Rule, analysis: Analysis, finding: Finding) -> bool:
    """True when the variant evaded because a filter selection now matches it."""
    for outcome in analysis.evaded:
        variant = outcome.result.variant
        if (
            outcome.event_index == finding.event_index
            and variant.mutation_name == finding.mutation_name
        ):
            return match_selection(rule.selections[finding.condition], variant.event)
    return False


def _propose(
    finding: Finding, events: Sequence[Event], detected: Sequence[int], proposals: Proposals
) -> bool:
    """Add the selections that would catch this evasion; False when none applies."""
    added = False
    signals = finding.remaining_signals
    if "OriginalFileName" in signals:
        values = _field_values(events, detected, "OriginalFileName")
        if values:
            proposals.setdefault(
                "original_file_name",
                (
                    [{"OriginalFileName": values}],
                    f"OriginalFileName is {_listing(values)} (survives {finding.mutation_name})",
                ),
            )
            added = True
    if "CommandLine" in signals:
        maps = []
        for index in detected:
            tokens = significant_arguments(events[index].get("CommandLine"))
            if tokens:
                maps.append({"CommandLine|contains|all": tokens})
        if maps:
            shown = " / ".join(_listing(m["CommandLine|contains|all"]) for m in maps)
            proposals.setdefault(
                "command_line",
                (
                    maps,
                    f"CommandLine contains all of {shown} (survives {finding.mutation_name})",
                ),
            )
            added = True
    if finding.field == "Image" and finding.mutation_name == "change_path":
        names = _image_names(events, detected)
        if names:
            values = [f"\\{escape_value(name)}" for name in names]
            proposals.setdefault(
                "image_name",
                (
                    [{"Image|endswith": values}],
                    f"Image ends with {_listing(values)} (survives {finding.mutation_name})",
                ),
            )
            added = True
    return added


def _image_names(events: Sequence[Event], detected: Sequence[int]) -> list[str]:
    """File names of the executables of the detected baselines."""
    names = []
    for index in detected:
        image = events[index].get("Image")
        if isinstance(image, str) and basename(image):
            names.append(basename(image))
    return _unique(names)


def _field_values(events: Sequence[Event], detected: Sequence[int], field: str) -> list[str]:
    """Escaped values of ``field`` from every detected baseline, or [] if one lacks it."""
    values = []
    for index in detected:
        value = events[index].get(field)
        if not isinstance(value, str) or not value:
            return []
        values.append(escape_value(value))
    return _unique(values)


def significant_arguments(command_line: object) -> list[str]:
    """Arguments worth matching on: no executable, flags, paths or short words.

    A token is kept when it has at least ``MIN_TOKEN_LENGTH`` characters and
    contains punctuation (``privilege::debug``), or is long on its own.
    """
    if not isinstance(command_line, str):
        return []
    tokens: list[str] = []
    for raw in split_args(command_line)[1:]:
        token = raw.strip("\"'")
        if not token or is_flag(token) or "\\" in token or "/" in token:
            continue
        has_punctuation = any(not c.isalnum() for c in token)
        long_enough = len(token) >= MIN_PLAIN_TOKEN_LENGTH
        if len(token) >= MIN_TOKEN_LENGTH and (has_punctuation or long_enough):
            tokens.append(escape_value(token))
    return _unique(tokens)[:MAX_TOKENS]


def escape_value(value: str) -> str:
    """Escape Sigma wildcards so a copied value matches literally."""
    out = []
    for i, char in enumerate(value):
        following = value[i + 1] if i + 1 < len(value) else ""
        if char in "*?" or (char == "\\" and following in ("*", "?", "\\")):
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def filter_names(rule: Rule) -> tuple[str, ...]:
    """Selections the condition uses under ``not`` (filters)."""
    found: list[str] = []

    def walk(node: Node, negated: bool) -> None:
        if isinstance(node, Ref):
            if negated:
                found.append(node.name)
        elif isinstance(node, Of):
            if negated:
                found.extend(node.names)
        elif isinstance(node, Not):
            walk(node.child, not negated)
        else:
            for child in node.children:
                walk(child, negated)

    walk(parse_condition(rule.condition, rule.selections), negated=False)
    return tuple(_unique(found))


def _build(rule: Rule, proposals: Proposals, unresolved: list[str]) -> Improvement:
    """Assemble, serialise and re-validate the improved rule."""
    raw = copy.deepcopy(dict(rule.raw))
    detection = dict(raw.get("detection", {}))
    detection.pop("condition", None)
    names: list[str] = []
    changes: list[str] = []
    for key, (maps, change) in proposals.items():
        name = _free_name(f"{PREFIX}{key}", detection)
        detection[name] = maps[0] if len(maps) == 1 else maps
        names.append(name)
        changes.append(f"added '{name}': {change}")
    added = " or ".join(names)
    filters = filter_names(rule)
    if filters:
        guard = " and ".join(f"not {name}" for name in filters)
        added = f"({added}) and {guard}"
        changes.append(f"kept the filters on the new selections: {', '.join(filters)}")
    new_condition = f"({rule.condition}) or ({added})"
    detection["condition"] = new_condition
    raw["detection"] = detection
    raw["title"] = f"{rule.title} (improved by YAGTHA)"
    raw["id"] = str(uuid.uuid5(_ID_NAMESPACE, f"{rule.id}|{new_condition}"))
    raw["description"] = (
        f"Derived by YAGTHA from rule {rule.id}. Adds selections on evidence that stayed "
        "the same in the variants that evaded the original rule."
    )
    raw["related"] = [{"id": rule.id, "type": "derived"}]
    yaml_text = yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=100)
    new_rule = parse_rule(yaml_text)
    rationale = (
        "The original rule depends on details the attacker controls. The new selections "
        "match evidence that stayed the same in the evading variants."
    )
    return Improvement(
        new_rule=new_rule,
        changes=tuple(changes),
        rationale=rationale,
        unresolved=tuple(unresolved),
        yaml_text=yaml_text,
    )


def _free_name(base: str, taken: dict[Any, Any]) -> str:
    """``base``, or ``base_2``, ``base_3``... if a selection already uses it."""
    name, counter = base, 2
    while name in taken:
        name = f"{base}_{counter}"
        counter += 1
    return name


def _listing(values: Sequence[str]) -> str:
    return "[" + ", ".join(f"'{v}'" for v in values) + "]"


def _unique(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(items))
