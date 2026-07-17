"""Tests for loading events from JSON."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from yagtha.errors import EventValidationError
from yagtha.events import MAX_EVENTS, MAX_EVENTS_BYTES, load_events, validate_events


def write(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "events.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_loads_list_and_single_object(tmp_path: Path) -> None:
    assert load_events(write(tmp_path, [{"Image": "a", "EventID": 1}])) == [
        {"Image": "a", "EventID": 1}
    ]
    assert load_events(write(tmp_path, {"Image": "a"})) == [{"Image": "a"}]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "non-empty"),
        ("text", "non-empty"),
        ([1], "not a JSON object"),
        ([{"Image": {"nested": 1}}], "values must be"),
        ([{"Image": ["a"]}], "values must be"),
        ([{"CommandLine": "a" * 40_000}], "longer than"),
        ([{f"f{i}": 1 for i in range(201)}], "more than 200 fields"),
    ],
)
def test_invalid_events(data: object, message: str) -> None:
    with pytest.raises(EventValidationError, match=message):
        validate_events(data)


def test_too_many_events() -> None:
    with pytest.raises(EventValidationError, match="more than"):
        validate_events([{}] * (MAX_EVENTS + 1))


def test_bad_json_missing_file_and_size(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[{", encoding="utf-8")
    with pytest.raises(EventValidationError, match="not valid JSON"):
        load_events(bad)
    with pytest.raises(EventValidationError, match="cannot read"):
        load_events(tmp_path / "missing.json")
    big = tmp_path / "big.json"
    big.write_text(" " * (MAX_EVENTS_BYTES + 1), encoding="utf-8")
    with pytest.raises(EventValidationError, match="larger than"):
        load_events(big)
