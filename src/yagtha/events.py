"""Load log events from JSON.

Events are untrusted input: the file is size limited, parsed with the
standard ``json`` module, and every event must be a flat object whose
values are strings, numbers, booleans or null.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from yagtha.errors import EventValidationError

MAX_EVENTS_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 1_000
MAX_FIELDS = 200
MAX_VALUE_LENGTH = 32_768

EventDict = dict[str, str | int | float | bool | None]


def load_events(path: str | Path) -> list[EventDict]:
    """Read a JSON file holding a list of events (or a single event)."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise EventValidationError(f"cannot read events file {file_path}: {exc.strerror}") from exc
    if size > MAX_EVENTS_BYTES:
        raise EventValidationError(
            f"events file {file_path} is larger than {MAX_EVENTS_BYTES} bytes"
        )
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventValidationError(f"events file {file_path} is not valid JSON: {exc}") from exc
    return validate_events(data)


def validate_events(data: Any) -> list[EventDict]:
    """Check parsed JSON and return it as a list of event dictionaries."""
    items = [data] if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise EventValidationError("events must be a non-empty JSON list of objects")
    if len(items) > MAX_EVENTS:
        raise EventValidationError(f"more than {MAX_EVENTS} events")
    return [_validate_event(index, item) for index, item in enumerate(items)]


def _validate_event(index: int, item: Any) -> EventDict:
    """Validate one event object."""
    if not isinstance(item, dict):
        raise EventValidationError(f"event {index} is not a JSON object")
    if len(item) > MAX_FIELDS:
        raise EventValidationError(f"event {index} has more than {MAX_FIELDS} fields")
    event: EventDict = {}
    for key, value in item.items():
        if not isinstance(value, str | int | float | bool) and value is not None:
            raise EventValidationError(
                f"event {index}, field '{key}': values must be strings, numbers, booleans or null"
            )
        if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
            raise EventValidationError(
                f"event {index}, field '{key}' is longer than {MAX_VALUE_LENGTH} characters"
            )
        event[str(key)] = value
    return event
