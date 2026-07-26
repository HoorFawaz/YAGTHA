"""Load a Sigma rule from YAML into the internal ``Rule`` model.

The YAML is untrusted input: it is parsed only with ``yaml.safe_load``, size
limited, and validated field by field. Anything outside the supported Sigma
subset raises ``UnsupportedRuleFeatureError`` instead of being ignored.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import regex
import yaml

from yagtha.condition import parse_condition
from yagtha.errors import RuleParseError, RuleValidationError, UnsupportedRuleFeatureError
from yagtha.models import FieldCondition, Modifier, Rule, RuleValue, Selection

MAX_RULE_BYTES = 256 * 1024
MAX_SELECTIONS = 64
MAX_VALUES_PER_FIELD = 256
MAX_REGEX_LENGTH = 512

SUPPORTED_LOGSOURCE = {"category": "process_creation", "product": "windows"}
SIGMA_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
UNSUPPORTED_DETECTION_KEYS = frozenset({"timeframe"})

_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
_SELECTION_NAME_RE = re.compile(r"^[A-Za-z0-9_\-.]+$")
# A quantified group that itself contains a quantifier, e.g. (a+)+ or (\w*)*,
# is the classic catastrophic-backtracking shape.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*}][^()]*\)\s*[+*{]")
_MATCH_MODIFIERS = frozenset(
    {Modifier.CONTAINS, Modifier.STARTSWITH, Modifier.ENDSWITH, Modifier.RE}
)


def load_rule(path: str | Path) -> Rule:
    """Read and parse a Sigma rule file."""
    return parse_rule(read_rule_text(path))


def read_rule_text(path: str | Path) -> str:
    """Read a rule file as text, with the same size limit as ``load_rule``."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise RuleParseError(f"cannot read rule file {file_path}: {exc.strerror}") from exc
    if size > MAX_RULE_BYTES:
        raise RuleParseError(f"rule file {file_path} is larger than {MAX_RULE_BYTES} bytes")
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleParseError(f"cannot read rule file {file_path}: {exc}") from exc
    return text


def parse_rule(text: str) -> Rule:
    """Parse Sigma rule YAML text into a validated ``Rule``."""
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        raise RuleParseError(f"rule is larger than {MAX_RULE_BYTES} bytes")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleParseError(f"rule is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleValidationError("rule must be a YAML mapping")
    return _build_rule(data)


def _build_rule(data: Mapping[str, Any]) -> Rule:
    """Validate the top-level keys and build the ``Rule``."""
    title = _require_str(data, "title")
    rule_id = _optional_str(data, "id") or _slug(title)
    level = _optional_str(data, "level") or "medium"
    if level not in SIGMA_LEVELS:
        raise RuleValidationError(f"unknown level '{level}'")
    logsource = _parse_logsource(data.get("logsource"))
    selections, condition = _parse_detection(data.get("detection"))
    return Rule(
        id=rule_id,
        title=title,
        logsource=logsource,
        selections=selections,
        condition=condition,
        level=level,
        description=_optional_str(data, "description") or "",
        raw=dict(data),
    )


def _parse_logsource(value: Any) -> dict[str, str]:
    """Check the rule targets Windows process creation events."""
    if not isinstance(value, dict):
        raise RuleValidationError("'logsource' must be a mapping")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise RuleValidationError("'logsource' keys and values must be strings")
    logsource = dict(value)
    for key, expected in SUPPORTED_LOGSOURCE.items():
        if logsource.get(key) != expected:
            raise UnsupportedRuleFeatureError(
                f"only {SUPPORTED_LOGSOURCE} rules are supported, got logsource {logsource}"
            )
    return logsource


def _parse_detection(value: Any) -> tuple[dict[str, Selection], str]:
    """Parse the selections and the condition of the detection block."""
    if not isinstance(value, dict):
        raise RuleValidationError("'detection' must be a mapping")
    for key in UNSUPPORTED_DETECTION_KEYS & set(value):
        raise UnsupportedRuleFeatureError(f"detection key '{key}' is not supported")
    condition = _parse_condition_value(value.get("condition"))
    names = [str(key) for key in value if key != "condition"]
    if not names:
        raise RuleValidationError("detection has no selections")
    if len(names) > MAX_SELECTIONS:
        raise RuleValidationError(f"detection has more than {MAX_SELECTIONS} selections")
    selections = {name: _parse_selection(name, value[name]) for name in names}
    parse_condition(condition, selections)
    return selections, condition


def _parse_condition_value(value: Any) -> str:
    """Accept a condition string, or a list of them (combined with OR)."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return " or ".join(f"({item.strip()})" for item in value)
    raise RuleValidationError("detection 'condition' must be a non-empty string")


def parse_selection(name: str, value: Any) -> Selection:
    """Parse and validate one selection (a map, or a list of maps)."""
    return _parse_selection(name, value)


def _parse_selection(name: str, value: Any) -> Selection:
    """Parse one named selection (a map, or a list of maps)."""
    if not _SELECTION_NAME_RE.match(name):
        raise RuleValidationError(f"invalid selection name '{name}'")
    if isinstance(value, dict):
        maps = [value]
    elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
        maps = value
    elif isinstance(value, list):
        raise UnsupportedRuleFeatureError(
            f"selection '{name}': keyword lists (values without a field name) are not supported"
        )
    else:
        raise RuleValidationError(f"selection '{name}' must be a mapping or a list of mappings")
    alternatives = tuple(_parse_map(name, item) for item in maps)
    return Selection(name=name, alternatives=alternatives)


def _parse_map(selection: str, mapping: Mapping[Any, Any]) -> tuple[FieldCondition, ...]:
    """Parse one map of ``Field|modifiers: value(s)`` entries."""
    if not mapping:
        raise RuleValidationError(f"selection '{selection}' contains an empty mapping")
    return tuple(_parse_field(selection, str(key), raw) for key, raw in mapping.items())


def _parse_field(selection: str, key: str, raw: Any) -> FieldCondition:
    """Parse one field key with its modifiers and values."""
    field_name, *modifier_names = key.split("|")
    if not _FIELD_NAME_RE.match(field_name):
        raise RuleValidationError(f"selection '{selection}': invalid field name '{field_name}'")
    modifiers = _parse_modifiers(selection, field_name, modifier_names)
    values = _parse_values(selection, field_name, raw)
    if Modifier.RE in modifiers:
        for item in values:
            _check_regex(selection, field_name, item)
    return FieldCondition(field=field_name, modifiers=modifiers, values=values)


def _parse_modifiers(selection: str, field_name: str, names: list[str]) -> tuple[Modifier, ...]:
    """Map modifier names to ``Modifier`` and reject unsupported combinations."""
    modifiers: list[Modifier] = []
    for name in names:
        try:
            modifier = Modifier(name)
        except ValueError:
            raise UnsupportedRuleFeatureError(
                f"selection '{selection}', field '{field_name}': modifier '{name}' is not supported"
            ) from None
        if modifier in modifiers:
            raise RuleValidationError(
                f"selection '{selection}', field '{field_name}': modifier '{name}' is repeated"
            )
        modifiers.append(modifier)
    if len(_MATCH_MODIFIERS.intersection(modifiers)) > 1:
        raise RuleValidationError(
            f"selection '{selection}', field '{field_name}': "
            "use only one of contains, startswith, endswith, re"
        )
    return tuple(modifiers)


def _parse_values(selection: str, field_name: str, raw: Any) -> tuple[RuleValue, ...]:
    """Normalise a single value or a list of values."""
    items = raw if isinstance(raw, list) else [raw]
    if not items:
        raise RuleValidationError(f"selection '{selection}', field '{field_name}' has no values")
    if len(items) > MAX_VALUES_PER_FIELD:
        raise RuleValidationError(
            f"selection '{selection}', field '{field_name}' has more than "
            f"{MAX_VALUES_PER_FIELD} values"
        )
    for item in items:
        if not isinstance(item, str | int | float | bool) and item is not None:
            raise RuleValidationError(
                f"selection '{selection}', field '{field_name}': "
                f"values must be strings, numbers, booleans or null, got {type(item).__name__}"
            )
    return tuple(items)


def _check_regex(selection: str, field_name: str, value: RuleValue) -> None:
    """Reject regexes that are not strings, too long, invalid or backtracking-prone."""
    where = f"selection '{selection}', field '{field_name}'"
    if not isinstance(value, str):
        raise RuleValidationError(f"{where}: 're' values must be strings")
    if len(value) > MAX_REGEX_LENGTH:
        raise RuleValidationError(f"{where}: regex is longer than {MAX_REGEX_LENGTH} characters")
    if _NESTED_QUANTIFIER_RE.search(value):
        raise UnsupportedRuleFeatureError(
            f"{where}: nested quantifiers like (a+)+ are rejected (catastrophic backtracking)"
        )
    try:
        regex.compile(value)
    except regex.error as exc:
        raise RuleValidationError(f"{where}: invalid regex: {exc}") from exc


def _require_str(data: Mapping[str, Any], key: str) -> str:
    """Return a required non-empty string field."""
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"rule needs a non-empty '{key}'")
    return value.strip()


def _optional_str(data: Mapping[str, Any], key: str) -> str | None:
    """Return an optional string field, or None when it is absent."""
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuleValidationError(f"'{key}' must be a string")
    return value.strip() or None


def _slug(text: str) -> str:
    """Build a readable id from a title when the rule has no id."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "rule"
