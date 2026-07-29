"""LLM provider interface and the Anthropic implementation.

The rest of YAGTHA only sees ``LLMProvider.complete_json``: a system prompt,
a user prompt and a JSON schema in, parsed JSON out. Tests use a fake
provider, so no test ever calls a real model.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any, Protocol

from yagtha.errors import YagthaError

DEFAULT_MODEL = "claude-opus-5-5"
MAX_OUTPUT_TOKENS = 16_000
# Server-side fallback: if the model declines, the API retries on a model
# chosen by refusal category, inside the same call.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MODEL_ENV = "YAGTHA_LLM_MODEL"


class LLMError(YagthaError):
    """The LLM is not available, declined, or returned unusable output."""


class LLMProvider(Protocol):
    """Anything that can answer a prompt with JSON matching a schema."""

    def complete_json(self, system: str, prompt: str, schema: Mapping[str, Any]) -> Any:
        """Return the parsed JSON answer."""
        ...


class AnthropicProvider:
    """Claude through the official ``anthropic`` SDK.

    Credentials come from the environment (``ANTHROPIC_API_KEY``), never from
    a file or the command line. The model can be changed with
    ``YAGTHA_LLM_MODEL``.
    """

    def __init__(self, model: str | None = None) -> None:
        try:
            import anthropic
        except ImportError:
            raise LLMError(
                'the LLM features need the optional package: pip install -e ".[llm]"'
            ) from None
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise LLMError("set the ANTHROPIC_API_KEY environment variable to use the LLM")
        self._anthropic = anthropic
        self._client = anthropic.Anthropic()
        self.model = model or os.environ.get(MODEL_ENV) or DEFAULT_MODEL

    def complete_json(self, system: str, prompt: str, schema: Mapping[str, Any]) -> Any:
        """Ask the model for JSON constrained by ``schema``."""
        try:
            response = self._client.beta.messages.create(
                model=self.model,
                max_tokens=MAX_OUTPUT_TOKENS,
                betas=[FALLBACK_BETA],
                fallbacks="default",
                system=system,
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "effort": "medium",
                    "format": {"type": "json_schema", "schema": dict(schema)},
                },
            )
        except self._anthropic.APIError as exc:
            raise LLMError(f"LLM request failed: {exc}") from exc
        if response.stop_reason == "refusal":
            raise LLMError("the model declined this request")
        if response.stop_reason == "max_tokens":
            raise LLMError("the model's answer was cut off")
        text = next((block.text for block in response.content if block.type == "text"), "")
        return parse_json(text)


def parse_json(text: str) -> Any:
    """Parse the model's text as JSON, with a clear error when it is not."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"the model did not return valid JSON: {exc}") from exc
