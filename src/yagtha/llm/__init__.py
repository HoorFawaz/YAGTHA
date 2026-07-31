"""Optional LLM helpers. YAGTHA works fully without them.

They need ``pip install -e ".[llm]"`` and an Anthropic API key in the
``ANTHROPIC_API_KEY`` environment variable. Everything the model returns is
untrusted data: it is parsed as JSON, validated, and never executed.
"""
