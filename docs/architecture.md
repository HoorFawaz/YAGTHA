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

`pipeline.py` chains analysis, improvement and verification as plain
functions. The command line (`cli.py`) and the web UI (`app/streamlit_app.py`)
both call it, so they always produce the same result for the same input.

## Modules

| Module | Role |
| --- | --- |
| `models.py` | Frozen dataclasses: rule, selection, event, variant, finding, improvement, verification. |
| `rule_loader.py` | Reads a rule with `yaml.safe_load`, checks size limits and the supported subset. |
| `condition.py` | Parser for the `condition` expression (`and`, `or`, `not`, `1 of`, `all of`). |
| `evaluator.py` | Own Sigma-subset matcher: modifiers, wildcards without regex, guarded `re`. |
| `mutations/` | Registry of deterministic, behaviour-preserving mutations (process, PowerShell, command line). |
| `events.py` | Loads and validates event files (JSON list of flat objects, size limits). |
| `analyzer.py` | Runs the rule on every baseline and variant and explains each miss. |
| `improver.py` | Proposes an improved rule from evidence that survived the mutations. |
| `verifier.py` | Compares both rules on the variants and the benign corpus, builds regression cases. |
| `reporter.py` | Deterministic Markdown report and the overall verdict. |
| `exporter.py` | Writes the bundle inside `./output` only, or builds it as an in-memory zip. |
| `pipeline.py` | The full run as functions shared by the CLI and the web UI. |
| `cli.py` | `analyze`, `improve`, `run`, `list-mutations`. |
| `llm/` | Optional plain-language summary of a finished run (`yagtha run --explain`). |

## Analysis

- Each baseline event is checked first. A baseline the rule does not detect is
  reported, and its variants are not counted as evasions.
- Each mutation produces at most one variant per baseline (a mutation that does
  not apply to an event, such as `encode_cmdline` on a non-PowerShell process,
  produces none). A variant the rule
  misses is a finding: which selection stopped matching, which field caused it,
  and which fields still carry the original evidence.
- A finding is `confirmed` when putting that one field's original value back
  makes the rule fire again, and `likely` when more than one field is involved.

## Improvement and verification

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

## Report and export

- `yagtha run` writes one bundle per rule to `output/<rule name>/`:
  `original_rule.yml`, `improved_rule.yml`, `regression_cases.json`,
  `test_regression.py`, `analysis.json`, `report.md` (the improved rule, cases
  and test only when a fix was proposed; files of an earlier run that no longer
  apply are removed).
- The report is deterministic (no timestamps). Rule and event values are
  escaped before they go into Markdown, and the YAML block uses a fence longer
  than any backtick run in it, so untrusted text cannot change the page.
- The exporter resolves the output folder and refuses anything outside
  `./output`, uses fixed file names and a sanitised bundle name, and refuses
  symbolic links. `test_regression.py` is a static file with no value copied
  from the input.
- The web UI never writes to disk: it builds the same bundle as a zip in memory
  and offers it as a download.

## Optional AI summary

- `yagtha run --explain` sends only the computed results (counts, findings,
  changes, verdict) to the Anthropic API and adds a short plain-language
  summary to the report, labelled as AI-generated.
- The answer must match a JSON schema, is escaped like any untrusted text, and
  never changes a rule, a verdict or a test. The API key is read only from the
  `ANTHROPIC_API_KEY` environment variable.

## Samples and demo

- Four sample rules in `data/rules/`, each with synthetic baseline events in
  `data/malicious_events/`, share the benign corpus. `yagtha run --rule
  data/rules/` runs them all, and CI runs it on every push.
- `examples/mimikatz_demo/` is a committed bundle. `tests/test_samples.py`
  regenerates it and fails if it differs, so the README and demo always show
  real output.
