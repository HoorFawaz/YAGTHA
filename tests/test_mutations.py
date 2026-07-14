"""Tests for the mutation registry and every built-in mutation."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from yagtha.errors import YagthaError
from yagtha.evaluator import evaluate, matches
from yagtha.models import Rule, Variant
from yagtha.mutations import (
    UnknownMutationError,
    generate_variants,
    get_mutation,
    list_mutations,
)
from yagtha.mutations.cmdline import replace_executable, split_args
from yagtha.mutations.powershell import decode_script, encode_script
from yagtha.mutations.process import mixed_case

EXPECTED = {
    "add_noise_args",
    "alt_parent",
    "change_case",
    "change_path",
    "encode_cmdline",
    "rename_image",
    "reorder_args",
}

POWERSHELL_EVENT: dict[str, Any] = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "OriginalFileName": "PowerShell.EXE",
    "CommandLine": (
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output yagtha"'
    ),
    "ParentImage": "C:\\Windows\\explorer.exe",
    "ParentCommandLine": "C:\\Windows\\explorer.exe",
    "User": "LAB\\analyst",
}


def apply(name: str, event: dict[str, Any]) -> dict[str, object] | None:
    return get_mutation(name).apply(event)


# --- Registry -------------------------------------------------------------


def test_all_mutations_are_registered_with_descriptions() -> None:
    mutations = list_mutations()
    assert {m.name for m in mutations} == EXPECTED
    assert [m.name for m in mutations] == sorted(EXPECTED)
    assert all(m.description for m in mutations)


def test_unknown_mutation() -> None:
    with pytest.raises(UnknownMutationError, match="unknown mutation 'nope'"):
        get_mutation("nope")


@pytest.mark.parametrize("name", sorted(EXPECTED))
@pytest.mark.parametrize("fixture", ["mimikatz_event", "powershell_event"])
def test_original_event_is_never_modified(
    name: str, fixture: str, request: pytest.FixtureRequest
) -> None:
    event = request.getfixturevalue(fixture)
    before = copy.deepcopy(event)
    first = apply(name, event)
    second = apply(name, event)
    assert event == before
    assert first == second  # deterministic
    if first is not None:
        assert first is not event


@pytest.fixture
def powershell_event() -> dict[str, Any]:
    return copy.deepcopy(POWERSHELL_EVENT)


def test_generate_variants_starts_with_original(mimikatz_event: dict[str, Any]) -> None:
    variants = generate_variants(mimikatz_event)
    assert variants[0].mutation_name == "original"
    assert variants[0].event == mimikatz_event
    names = [v.mutation_name for v in variants[1:]]
    assert names == ["alt_parent", "change_case", "change_path", "rename_image"]


def test_generate_variants_with_selected_names(powershell_event: dict[str, Any]) -> None:
    variants = generate_variants(powershell_event, names=["encode_cmdline", "rename_image"])
    assert [v.mutation_name for v in variants] == ["original", "encode_cmdline", "rename_image"]


def test_generate_variants_limit(powershell_event: dict[str, Any]) -> None:
    with pytest.raises(YagthaError, match="more than 2 variants"):
        generate_variants(powershell_event, max_variants=2)


def test_mutation_that_changes_nothing_is_skipped() -> None:
    assert apply("rename_image", {"Image": "C:\\x\\update.exe"}) is None
    assert apply("change_case", {"Image": "C:\\1\\2"}) is None


# --- Process mutations ----------------------------------------------------


def test_rename_image_keeps_original_file_name(mimikatz_event: dict[str, Any]) -> None:
    result = apply("rename_image", mimikatz_event)
    assert result is not None
    assert result["Image"] == "C:\\Users\\analyst\\Downloads\\update.exe"
    assert result["OriginalFileName"] == "mimikatz.exe"
    assert str(result["CommandLine"]).startswith("update.exe ")


def test_rename_image_needs_an_image() -> None:
    assert apply("rename_image", {"CommandLine": "x"}) is None


def test_change_path_moves_to_another_folder(mimikatz_event: dict[str, Any]) -> None:
    result = apply("change_path", mimikatz_event)
    assert result is not None
    assert result["Image"] == "C:\\ProgramData\\mimikatz.exe"
    moved_again = apply("change_path", {"Image": "C:\\ProgramData\\a.exe"})
    assert moved_again is not None
    assert moved_again["Image"] == "C:\\Users\\Public\\a.exe"


def test_change_case(mimikatz_event: dict[str, Any]) -> None:
    result = apply("change_case", mimikatz_event)
    assert result is not None
    assert str(result["Image"]).endswith("\\MiMiKaTz.ExE")
    assert str(result["CommandLine"]).casefold() == mimikatz_event["CommandLine"].casefold()
    assert mixed_case("ab-cd") == "Ab-Cd"


def test_reorder_args_keeps_terminal_switch_last(powershell_event: dict[str, Any]) -> None:
    result = apply("reorder_args", powershell_event)
    assert result is not None
    assert result["CommandLine"] == (
        'powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Output yagtha"'
    )


@pytest.mark.parametrize(
    "command_line",
    [
        "tool.exe",
        "tool.exe -only",
        'cmd.exe /c "dir" /q',  # /c owns the rest of the line
        "mimikatz.exe privilege::debug exit",  # positional order may matter
    ],
)
def test_reorder_args_not_applicable(command_line: str) -> None:
    assert apply("reorder_args", {"Image": "C:\\x.exe", "CommandLine": command_line}) is None


def test_add_noise_args(powershell_event: dict[str, Any]) -> None:
    result = apply("add_noise_args", powershell_event)
    assert result is not None
    assert str(result["CommandLine"]).startswith("powershell.exe -NoLogo -NoProfile ")
    cmd = apply(
        "add_noise_args",
        {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c dir"},
    )
    assert cmd is not None
    assert cmd["CommandLine"] == "cmd.exe /d /c dir"


def test_add_noise_args_skips_unknown_tools(mimikatz_event: dict[str, Any]) -> None:
    assert apply("add_noise_args", mimikatz_event) is None


def test_alt_parent(mimikatz_event: dict[str, Any], powershell_event: dict[str, Any]) -> None:
    from_cmd = apply("alt_parent", mimikatz_event)
    from_explorer = apply("alt_parent", powershell_event)
    assert from_cmd is not None
    assert from_explorer is not None
    assert from_cmd["ParentImage"] == "C:\\Windows\\explorer.exe"
    assert from_cmd["ParentCommandLine"] == "C:\\Windows\\explorer.exe"
    assert from_explorer["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"


# --- PowerShell -----------------------------------------------------------


def test_encode_and_decode_round_trip() -> None:
    assert decode_script(encode_script("Write-Output 'hi'")) == "Write-Output 'hi'"
    assert decode_script("not base64!") is None
    assert decode_script("A" * 9_000) is None


def test_encode_cmdline_plain_to_encoded(powershell_event: dict[str, Any]) -> None:
    result = apply("encode_cmdline", powershell_event)
    assert result is not None
    expected = encode_script("Write-Output yagtha")
    assert result["CommandLine"] == (
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {expected}"
    )


def test_encode_cmdline_encoded_to_plain(powershell_event: dict[str, Any]) -> None:
    encoded = encode_script("Write-Output yagtha")
    event = {**powershell_event, "CommandLine": f"powershell.exe -nop -enc {encoded}"}
    result = apply("encode_cmdline", event)
    assert result is not None
    assert result["CommandLine"] == 'powershell.exe -nop -Command "Write-Output yagtha"'


@pytest.mark.parametrize(
    "event",
    [
        {"Image": "C:\\x\\cmd.exe", "CommandLine": "cmd.exe -Command x"},
        {"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell.exe -NoProfile"},
        {"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell.exe -enc !!!"},
        {"Image": "C:\\x\\powershell.exe"},
    ],
)
def test_encode_cmdline_not_applicable(event: dict[str, Any]) -> None:
    assert apply("encode_cmdline", event) is None


# --- Helpers --------------------------------------------------------------


def test_split_args_keeps_quotes() -> None:
    assert split_args('a.exe  "x y"  -z') == ["a.exe", '"x y"', "-z"]


def test_replace_executable_handles_full_path_and_quotes() -> None:
    old, new = "C:\\a\\tool.exe", "C:\\b\\new.exe"
    assert replace_executable('"C:\\a\\tool.exe" -x', old, new) == '"C:\\b\\new.exe" -x'
    assert replace_executable("tool.exe -x", old, new) == "new.exe -x"
    assert replace_executable("other.exe -x", old, new) == "other.exe -x"
    assert replace_executable("", old, new) == ""


# --- The brief's example: a rename evades the image-name rule ------------


def test_mimikatz_rule_against_all_variants(
    mimikatz_rule: Rule, mimikatz_event: dict[str, Any]
) -> None:
    results = {
        v.mutation_name: evaluate(mimikatz_rule, v) for v in generate_variants(mimikatz_event)
    }
    caught = {name for name, result in results.items() if result.matched}
    assert caught == {"original", "alt_parent", "change_case", "change_path"}
    assert results["rename_image"].failed_fields == {"selection": ("Image",)}


def test_variant_still_matches_on_original_file_name(mimikatz_event: dict[str, Any]) -> None:
    from yagtha.rule_loader import parse_rule

    robust = parse_rule(
        "title: t\nlogsource: {category: process_creation, product: windows}\n"
        "detection:\n  sel:\n    OriginalFileName: mimikatz.exe\n  condition: sel\n"
    )
    renamed = apply("rename_image", mimikatz_event)
    assert renamed is not None
    assert matches(robust, renamed)
    assert evaluate(robust, Variant("rename_image", renamed)).matched
