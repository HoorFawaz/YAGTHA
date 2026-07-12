"""Command-line entry point.

The ``analyze``, ``improve``, ``run`` and ``list-mutations`` commands arrive in
later phases; for now the CLI only reports its version.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from yagtha import __version__


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="yagtha",
        description="Test how robust Sigma detection rules are against attacker variations.",
    )
    parser.add_argument("--version", action="version", version=f"yagtha {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    build_parser().parse_args(argv)
    print("yagtha: commands are not available yet (coming in Phase 3). Try --help.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
