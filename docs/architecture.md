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
| `llm/` (optional) | 7 | Planned |

## Improvement and verification (Phase 4)

- The improver only copies values from baseline events the original rule
  detects, and only from fields the analyzer found unchanged in an evading
  variant (`OriginalFileName`, significant `CommandLine` arguments, the
  executable name when only its folder moved). Copied values have Sigma
  wildcards escaped.
- New selections are named `yagtha_*`, OR-ed with the original condition,
  and keep every `not` filter of the original rule. Evasions caused by a
  filter, or with nothing left to match on, are listed as not fixed.
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

This document is completed in Phase 6.
