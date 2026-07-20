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
| `reporter.py`, `exporter.py`, `cli.py` (`run`) | 5 | Planned |
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

This document is completed in Phase 6.
