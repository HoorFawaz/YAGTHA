# Threat model

YAGTHA reads rules and logs written by other people. Both are treated as
**untrusted data**: nothing in them is ever executed.

| Threat | Protection |
| --- | --- |
| YAML that builds Python objects (`!!python/object`) | Only `yaml.safe_load` is used. |
| Huge files or huge rules (resource exhaustion) | Size limits on files, selections, values and conditions. |
| Regex that backtracks forever (ReDoS) | Length limit, nested quantifiers rejected, time-limited search. |
| Wildcard values crafted to be slow | Linear wildcard matcher, no regex conversion. |
| Deeply nested conditions (stack exhaustion) | Nesting depth limit. |
| Unsupported Sigma features giving wrong results | Clear `UnsupportedRuleFeatureError`, never ignored. |
| Writing files outside the output folder (path traversal) | Exporter resolves paths, writes only inside `./output`, fixed file names, refuses symbolic links. |
| Rule or event text changing the Markdown report | Values escaped; YAML shown in a fence longer than any backtick run. |
| Code injection through generated tests | `test_regression.py` is static; cases are data in JSON, validated when loaded. |
| LLM output used as data | Optional module; output validated against the event schema (Phase 7). |
| Secrets in the repository | None needed; any API key comes from an environment variable. |

All sample rules and events are synthetic. YAGTHA never runs malware or a sandbox.
