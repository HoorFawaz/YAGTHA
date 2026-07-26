# Architecture

```
Sigma rule (YAML) ──> rule_loader ──> Rule
                                       │
baseline events ──> mutations ──> variants ──> evaluator ──> analyzer ──> findings
                                                                │
                                         improver ──> verifier (variants + benign events)
                                                                │
                                                reporter + exporter ──> output/
```

| Module | Phase | Status |
| --- | --- | --- |
| `models.py` | 1 | Done |
| `rule_loader.py` | 1 | Done |
| `condition.py` (condition parser, used by the loader and the evaluator) | 1 | Done |
| `evaluator.py` | 1 | Done |
| `mutations/` (registry, process, PowerShell, command-line helpers) | 2 | Done |
| `events.py`, `analyzer.py`, `cli.py` (`analyze`, `list-mutations`) | 3 | Done |
| `improver.py`, `verifier.py`, `cli.py` (`improve`), `data/benign_events/` | 4 | Done |
| `reporter.py`, `exporter.py`, `cli.py` (`run`) | 5 | Done |
| Sample rules, `examples/mimikatz_demo`, docs, screenshots | 6 | Done |
| `llm/`, Streamlit UI (optional) | 7 | Not included |

## Improvement and verification (Phase 4)

- For each evasion the improver takes the field that stopped matching in one
  selection and tries to replace only that field with evidence copied from the
  same baseline event: `OriginalFileName` or the executable name for a defeated
  `Image`, and distinctive arguments (`CommandLine|contains|all`) for a defeated
  `Image` or `CommandLine`. Every other field of the selection is kept.
- A replacement is kept only if it matches both the baseline and the evading
  variant. Replacements go into `yagtha_<selection>`, and the condition is
  rewritten from its syntax tree so `<selection>` becomes
  `(<selection> or yagtha_<selection>)`; filters are untouched.
- Evasions caused by a filter, or with nothing safe to match on, are reported
  as not fixed (insufficient evidence). Copied values have Sigma wildcards escaped.
- The improved rule is written with `yaml.safe_dump`, then parsed again with
  the normal loader, so it is checked like any input rule. It gets a
  deterministic id and `related: derived` pointing to the original.
- The verifier runs both rules on the same variants and on the benign corpus.
  It passes only with no regression and no new false positive. What the
  improved rule gets right becomes regression cases (`match` / `no_match`).

## Report and export (Phase 5)

- `yagtha run` chains analysis, improvement and verification, then writes one
  bundle per rule to `output/<rule name>/`: `original_rule.yml`,
  `improved_rule.yml`, `regression_cases.json`, `test_regression.py`,
  `analysis.json`, `report.md` (the improved rule, cases and test only when a fix
  was proposed; files of an earlier run that no longer apply are removed).
- The report is deterministic (no timestamps). Rule and event values are
  escaped before they go into Markdown, and the YAML block uses a fence longer
  than any backtick run in it, so untrusted text cannot change the page.
- The exporter resolves the output folder and refuses anything outside
  `./output`, uses fixed file names and a sanitised bundle name, and refuses
  symbolic links. `test_regression.py` is a static file with no value copied
  from the input.

## Demo and docs (Phase 6)

- Four sample rules in `data/rules/`, each with synthetic baseline events in
  `data/malicious_events/`, share the benign corpus. `yagtha run --rule
  data/rules/` runs them all, and CI runs it on every push.
- `examples/mimikatz_demo/` is a committed bundle. `tests/test_samples.py`
  regenerates it and fails if it differs, so the README and demo always show
  real output.
