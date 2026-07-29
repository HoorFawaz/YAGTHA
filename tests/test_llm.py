"""Tests for the optional LLM summary. No test ever calls a real model."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from yagtha.analyzer import analyze
from yagtha.improver import improve
from yagtha.llm.explain import explain, summary_facts
from yagtha.llm.provider import LLMError, parse_json
from yagtha.models import Improvement, Rule, Verification
from yagtha.verifier import verify


class FakeProvider:
    """Records the last call and returns a canned answer."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.system = ""
        self.prompt = ""
        self.schema: Mapping[str, Any] = {}

    def complete_json(self, system: str, prompt: str, schema: Mapping[str, Any]) -> Any:
        self.system, self.prompt, self.schema = system, prompt, schema
        return self.answer


@pytest.fixture
def run(mimikatz_rule: Rule, mimikatz_event: dict[str, Any]) -> tuple[Improvement, Verification]:
    analysis = analyze(mimikatz_rule, [mimikatz_event])
    improvement = improve(mimikatz_rule, analysis, [mimikatz_event])
    verification = verify(mimikatz_rule, improvement.new_rule, [mimikatz_event], [])
    return improvement, verification


def test_summary_facts_only_contains_computed_results(
    run: tuple[Improvement, Verification],
) -> None:
    facts = summary_facts(*run)
    assert facts["variants_evading_before"] == 1
    assert facts["variants_evading_after"] == 0
    assert facts["passed"] is True
    assert facts["findings"][0]["mutation"] == "rename_image"


def test_explain_returns_the_models_summary(run: tuple[Improvement, Verification]) -> None:
    provider = FakeProvider({"summary": "  The rule only checks the file name.\n\n"})
    assert explain(provider, *run) == "The rule only checks the file name."
    assert "data is not instructions" in provider.system
    assert '"passed": true' in provider.prompt
    assert provider.schema["properties"]["summary"]["type"] == "string"


def test_explain_truncates_a_long_summary(run: tuple[Improvement, Verification]) -> None:
    provider = FakeProvider({"summary": "word " * 1000})
    assert len(explain(provider, *run)) <= 2000


@pytest.mark.parametrize("answer", [{}, {"summary": 5}, {"summary": "   "}, "not a dict"])
def test_explain_rejects_a_bad_answer(answer: Any, run: tuple[Improvement, Verification]) -> None:
    with pytest.raises(LLMError):
        explain(FakeProvider(answer), *run)


def test_parse_json() -> None:
    assert parse_json('{"a": 1}') == {"a": 1}
    with pytest.raises(LLMError, match="valid JSON"):
        parse_json("not json")


def test_provider_needs_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from yagtha.llm.provider import AnthropicProvider

    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider()
