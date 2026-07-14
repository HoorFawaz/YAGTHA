"""Small helpers for Windows paths and command lines.

Tokens keep their quotes, so ``join_args(split_args(text))`` rebuilds the
command line with single spaces between tokens.
"""

from __future__ import annotations

import ntpath


def split_args(command_line: str) -> list[str]:
    """Split a command line on spaces that are outside double quotes."""
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in command_line:
        if char == '"':
            in_quotes = not in_quotes
        if char.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def join_args(tokens: list[str]) -> str:
    """Join tokens back into one command line."""
    return " ".join(tokens)


def basename(path: str) -> str:
    """File name part of a Windows path."""
    return ntpath.basename(path)


def dirname(path: str) -> str:
    """Directory part of a Windows path."""
    return ntpath.dirname(path)


def is_flag(token: str) -> bool:
    """True for tokens like ``-NoProfile`` or ``/c``."""
    return len(token) > 1 and token[0] in "-/" and not token[1].isspace()


def replace_executable(command_line: str, old_image: str, new_image: str) -> str:
    """Swap the executable at the start of a command line, keeping its quoting.

    The first token may be the full path or just the file name; both forms
    are handled. Other tokens are left untouched.
    """
    tokens = split_args(command_line)
    if not tokens:
        return command_line
    first = tokens[0]
    quoted = first.startswith('"') and first.endswith('"') and len(first) > 1
    bare = first[1:-1] if quoted else first
    if bare.casefold() == old_image.casefold():
        replacement = new_image
    elif bare.casefold() == basename(old_image).casefold():
        replacement = basename(new_image)
    else:
        return command_line
    tokens[0] = f'"{replacement}"' if quoted else replacement
    return join_args(tokens)
