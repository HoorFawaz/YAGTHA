"""Tests for the command-line interface."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest

from yagtha.cli import EXIT_ERROR, EXIT_OK, default_benign_path, default_events_path, main

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


def test_default_benign_path() -> None:
    assert default_benign_path(RULE) == DATA / "benign_events" / "benign.json"


def test_improve_text_output() -> None:
    code, text = run("improve", "--rule", str(RULE))
    assert code == EXIT_OK
    assert "Original rule: 1 of 4 variants evade it" in text
    assert "added 'yagtha_original_file_name'" in text
    assert "condition: (selection) or (yagtha_original_file_name or yagtha_command_line)" in text
    assert "variants evading: 1 -> 0" in text
    assert "fixed      event0/rename_image" in text
    assert "benign events matched: 0 -> 0 (of 14)" in text
    assert text.rstrip().endswith("Result: PASSED")


def test_improve_json_output() -> None:
    code, text = run("improve", "--rule", str(RULE), "--json")
    assert code == EXIT_OK
    data = json.loads(text)
    assert data["changed"] is True
    assert data["verification"]["passed"] is True
    assert data["verification"]["fixed"] == ["event0/rename_image"]
    assert data["regression_cases"] == 19
    assert "yagtha_command_line" in data["improved_rule"]["yaml"]


def test_improve_without_evasion() -> None:
    code, text = run("improve", "--rule", str(RULE), "--mutations", "change_case")
    assert code == EXIT_OK
    assert "No evasion found, the rule is unchanged." in text
    assert "Result:" not in text


def test_improve_reports_false_positives(tmp_path: Path) -> None:
    benign = tmp_path / "benign.json"
    benign.write_text(
        json.dumps([{"Image": "C:\\Tools\\mimikatz.exe", "OriginalFileName": "mimikatz.exe"}]),
        encoding="utf-8",
    )
    code, text = run("improve", "--rule", str(RULE), "--benign", str(benign))
    assert code == EXIT_OK
    assert "benign events matched: 1 -> 1 (of 1)" in text
    assert "Result: PASSED" in text


def test_improve_warns_without_benign_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "malicious_events").mkdir()
    shutil.copy(RULE, tmp_path / "rules" / "mimikatz.yml")
    shutil.copy(DATA / "malicious_events" / "mimikatz.json", tmp_path / "malicious_events")
    code, text = run("improve", "--rule", str(tmp_path / "rules" / "mimikatz.yml"))
    assert code == EXIT_OK
    assert "false positives are not checked" in capsys.readouterr().err
    assert "benign events matched: 0 -> 0 (of 0)" in text


def test_improve_missing_explicit_benign_is_an_error(tmp_path: Path) -> None:
    code, _ = run("improve", "--rule", str(RULE), "--benign", str(tmp_path / "none.json"))
    assert code == EXIT_ERROR
