"""PowerShell mutation: switch between a plain and an encoded command.

``powershell -Command "<script>"`` and ``powershell -EncodedCommand <base64>``
run exactly the same script; the second hides every keyword from rules that
look at the command line. The mutation converts in both directions.
"""

from __future__ import annotations

import base64
import binascii

from yagtha.mutations.base import register
from yagtha.mutations.cmdline import basename, is_flag, join_args, split_args

POWERSHELL_IMAGES = frozenset({"powershell.exe", "pwsh.exe"})
MAX_ENCODED_LENGTH = 8_192

Fields = dict[str, object]


def encode_script(script: str) -> str:
    """Encode a script the way ``-EncodedCommand`` expects (UTF-16LE + base64)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def decode_script(encoded: str) -> str | None:
    """Decode an ``-EncodedCommand`` value, or None when it is not valid."""
    if len(encoded) > MAX_ENCODED_LENGTH:
        return None
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _switch_kind(token: str) -> str | None:
    """Classify a switch as ``command``, ``encoded`` or neither (PowerShell prefixes)."""
    if not is_flag(token):
        return None
    name = token[1:].casefold()
    if "encodedcommand".startswith(name):
        return "encoded"
    if "command".startswith(name):
        return "command"
    return None


def _unquote(text: str) -> str:
    """Remove one pair of surrounding double quotes."""
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


@register("encode_cmdline", "Switch PowerShell between a plain and a base64-encoded command.")
def encode_cmdline(event: Fields) -> Fields | None:
    image = event.get("Image")
    command_line = event.get("CommandLine")
    if not isinstance(image, str) or not isinstance(command_line, str):
        return None
    if basename(image).casefold() not in POWERSHELL_IMAGES:
        return None
    tokens = split_args(command_line)
    for index, token in enumerate(tokens[1:], start=1):
        kind = _switch_kind(token)
        rest = tokens[index + 1 :]
        if kind is None or not rest:
            continue
        if kind == "command":
            script = _unquote(join_args(rest))
            new_tail = ["-EncodedCommand", encode_script(script)]
        else:
            decoded = decode_script(rest[0])
            if decoded is None:
                return None
            new_tail = ["-Command", f'"{decoded}"']
        event["CommandLine"] = join_args([*tokens[:index], *new_tail])
        return event
    return None
