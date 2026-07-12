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
| `mutations/` | 2 | Planned |
| `analyzer.py` | 3 | Planned |
| `improver.py`, `verifier.py` | 4 | Planned |
| `reporter.py`, `exporter.py`, `cli.py` | 5 | Planned |
| `llm/` (optional) | 7 | Planned |

This document is completed in Phase 6.
