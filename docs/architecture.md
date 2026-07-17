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
| `improver.py`, `verifier.py` | 4 | Planned |
| `reporter.py`, `exporter.py`, `cli.py` (`run`) | 5 | Planned |
| `llm/` (optional) | 7 | Planned |

This document is completed in Phase 6.
