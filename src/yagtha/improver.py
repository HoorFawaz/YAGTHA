"""Propose a more robust rule using only evidence found in the events.

The improver never invents values. For each evasion it takes the part of
the rule that stopped matching (one field of one selection) and tries to
replace only that field with evidence copied from the baseline event:

* ``Image`` defeated (renamed or moved executable):
  ``OriginalFileName`` from the PE header, the executable's file name
  (``Image|endswith '\\<name>'``), or the significant command-line arguments;
* ``CommandLine`` defeated (reordered, extra switches, renamed executable):
  the significant arguments with ``CommandLine|contains|all``.

Every other field of that selection is kept, so the rule stays as specific
as before. A replacement is kept only if it matches both the baseline and
the evading variant. Replacements go into a new selection
``yagtha_<selection>``, and the condition uses ``(<selection> or
yagtha_<selection>)`` wherever it used ``<selection>``; filters and the rest
of the condition do not change. Evasions caused by a filter, or with no
evidence left to match on, are reported as unresolved instead of guessed.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import yaml

from yagtha.condition import And, Node, Not, Of, Or, Ref, parse_condition
from yagtha.evaluator import match_selection
from yagtha.models import Analysis, Event, FieldCondition, Finding, Improvement, Rule, Selection
from yagtha.mutations.cmdline import basename, is_flag, split_args
from yagtha.rule_loader import parse_rule, parse_selection

PREFIX = "yagtha_"
MAX_TOKENS = 4
MIN_TOKEN_LENGTH = 4
MIN_PLAIN_TOKEN_LENGTH = 8
# Fixed namespace so the same improvement always gets the same rule id.
_ID_NAMESPACE = uuid.UUID("0f4c8a52-6d1e-4b7a-9e3f-2a5c7d9b1e60")

# selection name -> list of (new map, change description)
Proposals = dict[str, list[tuple[dict[str, Any], str]]]


def improve(rule: Rule, analysis: Analysis, events: Sequence[Event]) -> Improvement:
    """Build an improved rule from the analysis of ``rule`` on ``events``."""
    proposals: Proposals = {}
    unresolved: list[str] = []
    for finding in analysis.findings:
        variant = _variant_event(analysis, finding)
        if match_selection(rule.selections[finding.condition], variant):
            unresolved.append(
                f"{finding.mutation_name}: filter '{finding.condition}' suppresses the alert; "
                "filters are not changed automatically, review it by hand"
            )
        elif not _propose(rule, finding, events[finding.event_index], variant, proposals):
            unresolved.append(
                f"{finding.mutation_name}: insufficient evidence, no unchanged field "
                f"can replace {finding.field} in '{finding.condition}'"
            )
    if not proposals:
        rationale = (
            "No evasion found, the rule is unchanged."
            if not analysis.findings
            else "Insufficient evidence: no field in the events still shows the behaviour."
        )
        return Improvement(
            new_rule=rule, changes=(), rationale=rationale, unresolved=tuple(_unique(unresolved))
        )
    return _build(rule, proposals, _unique(unresolved))


def _variant_event(analysis: Analysis, finding: Finding) -> Event:
    """The evading variant a finding is about."""
    for outcome in analysis.evaded:
        variant = outcome.result.variant
        if (
            outcome.event_index == finding.event_index
            and variant.mutation_name == finding.mutation_name
        ):
            return variant.event
    raise ValueError(f"no evading variant for finding {finding}")  # pragma: no cover


def _propose(
    rule: Rule, finding: Finding, baseline: Event, variant: Event, proposals: Proposals
) -> bool:
    """Add replacements for the defeated field; False when none is safe."""
    selection = rule.selections[finding.condition]
    raw_maps = _raw_maps(rule, finding.condition)
    added = False
    for index, alternative in enumerate(selection.alternatives):
        if not _uses(alternative, finding.field):
            continue
        if not match_selection(Selection(selection.name, (alternative,)), baseline):
            continue
        kept = {
            key: value
            for key, value in raw_maps[index].items()
            if str(key).split("|")[0] != finding.field
        }
        for entries, description in _candidates(finding.field, baseline):
            if set(entries) & set(kept):
                continue
            new_map = {**copy.deepcopy(kept), **entries}
            candidate = parse_selection(finding.condition, new_map)
            if not (match_selection(candidate, baseline) and match_selection(candidate, variant)):
                continue
            existing = proposals.setdefault(finding.condition, [])
            if all(new_map != seen for seen, _ in existing):
                existing.append(
                    (
                        new_map,
                        f"{finding.field} replaced by {description} "
                        f"(survives {finding.mutation_name})",
                    )
                )
            added = True
    return added


def _candidates(field: str, baseline: Event) -> list[tuple[dict[str, Any], str]]:
    """Possible replacements for ``field``, built only from the baseline's own values."""
    found: list[tuple[dict[str, Any], str]] = []
    tokens = significant_arguments(baseline.get("CommandLine"))
    if field == "Image":
        original = baseline.get("OriginalFileName")
        if isinstance(original, str) and original:
            value = escape_value(original)
            found.append(({"OriginalFileName": value}, f"OriginalFileName '{value}'"))
        image = baseline.get("Image")
        if isinstance(image, str) and basename(image):
            value = "\\" + escape_value(basename(image))
            found.append(({"Image|endswith": value}, f"Image ending with '{value}'"))
    if field in ("Image", "CommandLine") and tokens:
        found.append(
            (
                {"CommandLine|contains|all": tokens},
                f"CommandLine containing all of {_listing(tokens)}",
            )
        )
    return found


def _uses(alternative: Sequence[FieldCondition], field: str) -> bool:
    return any(condition.field == field for condition in alternative)


def _raw_maps(rule: Rule, name: str) -> list[Mapping[Any, Any]]:
    """The YAML maps of a selection, in the same order as its alternatives."""
    value = rule.raw["detection"][name]
    return [value] if isinstance(value, Mapping) else list(value)


def significant_arguments(command_line: object) -> list[str]:
    """Arguments worth matching on: no executable, flags, paths or short words.

    A token is kept when it has at least ``MIN_TOKEN_LENGTH`` characters and
    contains punctuation (``privilege::debug``), or is long on its own.
    """
    if not isinstance(command_line, str):
        return []
    tokens: list[str] = []
    for raw in split_args(command_line)[1:]:
        token = raw.strip("\"'").rstrip(",")
        if not token or is_flag(token) or "\\" in token or "/" in token or " " in token:
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


def render_condition(node: Node, replace: Mapping[str, str]) -> str:
    """Write a condition back as text, OR-ing each replaced selection with its new one."""
    if isinstance(node, Ref):
        if node.name in replace:
            return f"({node.name} or {replace[node.name]})"
        return node.name
    if isinstance(node, Of):
        parts = [render_condition(Ref(name), replace) for name in node.names]
        if len(parts) == 1:
            return parts[0]
        return "(" + (" and " if node.require_all else " or ").join(parts) + ")"
    if isinstance(node, Not):
        return f"not {_group(node.child, replace)}"
    joiner = " and " if isinstance(node, And) else " or "
    return joiner.join(_group(child, replace) for child in node.children)


def _group(node: Node, replace: Mapping[str, str]) -> str:
    text = render_condition(node, replace)
    return f"({text})" if isinstance(node, And | Or) else text


def _build(rule: Rule, proposals: Proposals, unresolved: list[str]) -> Improvement:
    """Assemble, serialise and re-validate the improved rule."""
    raw = copy.deepcopy(dict(rule.raw))
    old_detection = dict(raw.get("detection", {}))
    old_detection.pop("condition", None)
    taken = dict(old_detection)
    replace: dict[str, str] = {}
    detection: dict[str, Any] = {}
    changes: list[str] = []
    for name, value in old_detection.items():
        detection[name] = value
        if name not in proposals:
            continue
        new_name = _free_name(f"{PREFIX}{name}", taken)
        taken[new_name] = None
        replace[name] = new_name
        maps = [new_map for new_map, _ in proposals[name]]
        detection[new_name] = maps[0] if len(maps) == 1 else maps
        changes += [f"'{new_name}': {change}" for _, change in proposals[name]]
    tree = parse_condition(rule.condition, rule.selections)
    new_condition = render_condition(tree, replace)
    if isinstance(tree, Ref):
        new_condition = new_condition.removeprefix("(").removesuffix(")")
    changes.append(f"condition '{rule.condition}' becomes '{new_condition}'")
    detection["condition"] = new_condition
    raw["detection"] = detection
    raw["title"] = f"{rule.title} (improved by YAGTHA)"
    raw["id"] = str(uuid.uuid5(_ID_NAMESPACE, f"{rule.id}|{new_condition}"))
    raw["description"] = (
        f"Derived by YAGTHA from rule {rule.id}. Each defeated field can also be matched "
        "by evidence that stayed the same in the variants that evaded the original rule."
    )
    raw["related"] = [{"id": rule.id, "type": "derived"}]
    yaml_text = yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=100)
    new_rule = parse_rule(yaml_text)
    rationale = (
        "The original rule depends on details the attacker controls. Only the defeated "
        "field is given an alternative, taken from evidence that stayed the same in the "
        "evading variants; the rest of the rule is unchanged."
    )
    return Improvement(
        new_rule=new_rule,
        changes=tuple(changes),
        rationale=rationale,
        unresolved=tuple(unresolved),
        yaml_text=yaml_text,
    )


def _free_name(base: str, taken: Mapping[Any, Any]) -> str:
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
