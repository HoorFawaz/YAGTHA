"""Tests for the command-line interface."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from yagtha.cli import EXIT_ERROR, EXIT_OK, default_events_path, main

DATA = Path(__file__).resolve().parent.parent / "data"
RULE = DATA / "rules" / "mimikatz.yml"


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


def test_analyze_text_output() -> None:
    code, text = run("analyze", "--rule", str(RULE))
    assert code == EXIT_OK
    assert "Variants tested: 4 | caught: 3 | evaded: 1" in text
    assert "EVADED   rename_image" in text
    assert "[confirmed] selection:" in text
    assert "still visible in: OriginalFileName, CommandLine" in text


def test_analyze_json_output() -> None:
    code, text = run("analyze", "--rule", str(RULE), "--json")
    assert code == EXIT_OK
    data = json.loads(text)
    assert data["rule"]["id"] == "6a1f3c52-2b7e-4d8a-9c41-0e5b7f2d9a13"
    assert [f["mutation"] for f in data["findings"]] == ["rename_image"]
    assert data["findings"][0]["confidence"] == "confirmed"


def test_analyze_selected_mutations_and_no_evasion() -> None:
    code, text = run("analyze", "--rule", str(RULE), "--mutations", "change_case, change_path")
    assert code == EXIT_OK
    assert "No variant evaded the rule." in text


def test_analyze_with_explicit_events_and_undetected_baseline(tmp_path: Path) -> None:
    events = tmp_path / "events.json"
    events.write_text(json.dumps([{"Image": "C:\\Windows\\notepad.exe"}]), encoding="utf-8")
    code, text = run("analyze", "--rule", str(RULE), "--events", str(events))
    assert code == EXIT_OK
    assert "does not detect baseline event 0" in text


def test_errors_are_reported_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run("analyze", "--rule", str(tmp_path / "missing.yml"))
    assert code == EXIT_ERROR
    assert "yagtha: error: cannot read rule file" in capsys.readouterr().err
    code, _ = run("analyze", "--rule", str(RULE), "--mutations", "nope")
    assert code == EXIT_ERROR
    assert "unknown mutation 'nope'" in capsys.readouterr().err


def test_list_mutations() -> None:
    code, text = run("list-mutations")
    assert code == EXIT_OK
    assert text.splitlines()[0].startswith("add_noise_args")
    assert len(text.splitlines()) == 7


def test_command_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main([])
    assert "required" in capsys.readouterr().err


def test_default_events_path() -> None:
    assert default_events_path(RULE) == DATA / "malicious_events" / "mimikatz.json"
