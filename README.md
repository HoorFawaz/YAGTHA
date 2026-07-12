# YAGTHA (يقظة)

**Test how robust a Sigma detection rule is against simple attacker changes.**

YAGTHA takes a Sigma rule, checks whether it still fires when an attacker
changes small things (file name, path, letter case, command-line encoding...),
explains why it fails, proposes an improved rule, and verifies it.

> Similar tools exist (Sigma tooling, rule-testing utilities). YAGTHA focuses on
> testing the robustness of detection rules against behavioral variations, and on
> helping analysts fix fragile rules with verifiable improvements.

## Example

The rule below alerts when `Image` ends with `\mimikatz.exe`. An attacker
renames the file to `abc.exe` and the rule misses it, even though
`OriginalFileName` and `CommandLine` still show the same behavior.

```yaml
detection:
  selection:
    Image|endswith: '\mimikatz.exe'
  condition: selection
```

## Status

Work in progress, built phase by phase.

- [x] Phase 1: foundation (data model, safe rule loader, Sigma evaluator)
- [ ] Phase 2: mutations
- [ ] Phase 3: analysis
- [ ] Phase 4: improvement and verification
- [ ] Phase 5: report and export
- [ ] Phase 6: demo and docs

## Install and test

Needs Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Docs

- [Supported Sigma subset](docs/supported-sigma-subset.md)
- [Threat model](docs/threat-model.md)
- [Architecture](docs/architecture.md)

## Security

Rules and logs are treated as untrusted data and are never executed. All
sample data is synthetic. See the [threat model](docs/threat-model.md).

## License

MIT
