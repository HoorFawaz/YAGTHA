# Notes for Claude

The full project brief is "YAGTHA PROJECT BRIEF.pdf", kept by the owner (Hoor Fawaz).
Read it before changing code.

- Build phase by phase (brief section 9); stop after each phase with a short summary.
- Python 3.11+, type hints, small functions, docstrings, English comments, tests.
- `ruff check .`, `ruff format --check .`, `mypy`, `pytest` and `bandit -r src` must pass.
- Rules, logs and LLM output are untrusted data. `yaml.safe_load` only; never `eval`,
  `exec`, `pickle` or `shell=True`. Never write outside `output/`.
- Never invent results or metrics. All sample data is synthetic.
