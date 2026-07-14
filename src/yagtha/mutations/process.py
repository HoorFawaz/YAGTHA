"""Process mutations: rename_image, change_path, change_case, reorder_args,
add_noise_args and alt_parent.

Each one changes something an attacker controls while keeping the fields
that still reveal the behaviour (for example ``OriginalFileName``).
"""

from __future__ import annotations

from yagtha.mutations.base import register
from yagtha.mutations.cmdline import (
    basename,
    dirname,
    is_flag,
    join_args,
    replace_executable,
    split_args,
)

RENAMED_IMAGE = "update.exe"
ALTERNATE_DIRECTORIES = ("C:\\ProgramData", "C:\\Users\\Public")
ALTERNATE_PARENTS = ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe")
# Harmless switches that do not change what the process does.
NOISE_ARGS = {
    "powershell.exe": "-NoLogo",
    "pwsh.exe": "-NoLogo",
    "cmd.exe": "/d",
}

Fields = dict[str, object]


def _text(event: Fields, field: str) -> str | None:
    """Return a field as text, or None when it is missing or not a string."""
    value = event.get(field)
    return value if isinstance(value, str) and value else None


def _move_image(event: Fields, new_image: str) -> Fields:
    """Point ``Image`` to a new path and keep ``CommandLine`` consistent."""
    old_image = _text(event, "Image") or ""
    event["Image"] = new_image
    command_line = _text(event, "CommandLine")
    if command_line is not None:
        event["CommandLine"] = replace_executable(command_line, old_image, new_image)
    return event


@register("rename_image", "Rename the executable; OriginalFileName still shows the real tool.")
def rename_image(event: Fields) -> Fields | None:
    image = _text(event, "Image")
    if image is None or basename(image).casefold() == RENAMED_IMAGE:
        return None
    return _move_image(event, f"{dirname(image)}\\{RENAMED_IMAGE}")


@register("change_path", "Run the same executable from another folder.")
def change_path(event: Fields) -> Fields | None:
    image = _text(event, "Image")
    if image is None:
        return None
    current = dirname(image).casefold()
    target = next(d for d in ALTERNATE_DIRECTORIES if d.casefold() != current)
    return _move_image(event, f"{target}\\{basename(image)}")


def mixed_case(text: str) -> str:
    """Alternate upper and lower case on letters: ``mimikatz`` -> ``MiMiKaTz``."""
    result: list[str] = []
    upper = True
    for char in text:
        if char.isalpha():
            result.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            result.append(char)
    return "".join(result)


@register("change_case", "Mix upper and lower case in the file name and command line.")
def change_case(event: Fields) -> Fields | None:
    image = _text(event, "Image")
    if image is None:
        return None
    _move_image(event, f"{dirname(image)}\\{mixed_case(basename(image))}")
    command_line = _text(event, "CommandLine")
    if command_line is not None:
        event["CommandLine"] = mixed_case(command_line)
    return event


# Switches after which the rest of the line belongs to the switch
# (PowerShell -Command/-File/-EncodedCommand and their prefixes, cmd /c and /k).
TERMINAL_SWITCHES = ("command", "file", "encodedcommand", "k")
# Switches that never take a value.
BOOLEAN_SWITCHES = frozenset(
    {"noprofile", "nop", "nologo", "noninteractive", "noni", "noexit", "sta", "mta", "d", "q"}
)


def _is_terminal(flag: str) -> bool:
    """True when everything after ``flag`` must stay in place."""
    name = flag[1:].casefold()
    return any(full.startswith(name) for full in TERMINAL_SWITCHES)


def _flag_groups(tokens: list[str]) -> tuple[list[list[str]], list[str]]:
    """Split arguments into movable flag groups (a flag plus its value) and the rest.

    Parsing stops at the first positional token or terminal switch; that
    token and everything after it are returned unchanged as the rest.
    """
    groups: list[list[str]] = []
    index = 0
    while index < len(tokens) and is_flag(tokens[index]) and not _is_terminal(tokens[index]):
        group = [tokens[index]]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        takes_value = (
            tokens[index][1:].casefold() not in BOOLEAN_SWITCHES and ":" not in tokens[index]
        )
        if takes_value and following is not None and not is_flag(following):
            group.append(following)
            index += 1
        groups.append(group)
        index += 1
    return groups, tokens[index:]


@register("reorder_args", "Reverse the order of leading command-line switches.")
def reorder_args(event: Fields) -> Fields | None:
    command_line = _text(event, "CommandLine")
    if command_line is None:
        return None
    executable, *arguments = split_args(command_line)
    groups, rest = _flag_groups(arguments)
    if len(groups) < 2:
        return None
    reordered = [token for group in reversed(groups) for token in group]
    event["CommandLine"] = join_args([executable, *reordered, *rest])
    return event


@register("add_noise_args", "Add a harmless switch that does not change the behaviour.")
def add_noise_args(event: Fields) -> Fields | None:
    image = _text(event, "Image")
    command_line = _text(event, "CommandLine")
    if image is None or command_line is None:
        return None
    noise = NOISE_ARGS.get(basename(image).casefold())
    if noise is None:
        return None
    executable, *arguments = split_args(command_line)
    event["CommandLine"] = join_args([executable, noise, *arguments])
    return event


@register("alt_parent", "Start the same process from a different parent process.")
def alt_parent(event: Fields) -> Fields | None:
    parent = _text(event, "ParentImage") or ""
    new_parent = next(p for p in ALTERNATE_PARENTS if p.casefold() != parent.casefold())
    event["ParentImage"] = new_parent
    if "ParentCommandLine" in event:
        event["ParentCommandLine"] = new_parent
    return event
