"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from yagtha.models import Rule
from yagtha.rule_loader import load_rule

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture
def mimikatz_rule() -> Rule:
    """The fragile sample rule that only checks the image name."""
    return load_rule(DATA_DIR / "rules" / "mimikatz.yml")


@pytest.fixture
def mimikatz_event() -> dict[str, Any]:
    """The synthetic baseline event the mimikatz rule should catch."""
    events = json.loads((DATA_DIR / "malicious_events" / "mimikatz.json").read_text("utf-8"))
    return dict(events[0])
