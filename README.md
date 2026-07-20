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
- [x] Phase 2: mutations (7 behaviour-preserving attacker variations)
- [x] Phase 3: analysis (`yagtha analyze`)
- [x] Phase 4: improvement and verification (`yagtha improve`)
- [ ] Phase 5: report and export
- [ ] Phase 6: demo and docs

## Usage

```bash
yagtha analyze --rule data/rules/mimikatz.yml
```

Real output:

```text
Rule: Mimikatz Execution by Image Name (high)
Baseline events: 1 (1 detected)
Variants tested: 4 | caught: 3 | evaded: 1

  caught   alt_parent
  caught   change_case
  caught   change_path
  EVADED   rename_image
           [confirmed] selection: Image|endswith '\mimikatz.exe' no longer matches: Image changed from 'C:\Users\analyst\Downloads\mimikatz.exe' to 'C:\Users\analyst\Downloads\update.exe'
           still visible in: OriginalFileName, CommandLine
```

`confirmed` means YAGTHA put the field's original value back and the rule fired again,
so the cause is reproduced. `likely` means more than one changed field is involved.

Other options: `--events my_events.json`, `--mutations rename_image,change_path`,
`--json`, and `yagtha list-mutations`.

### Improve and verify

```bash
yagtha improve --rule data/rules/mimikatz.yml
```

Real output:

```text
Rule: Mimikatz Execution by Image Name (high)
Original rule: 1 of 4 variants evade it

Proposed changes:
  - added 'yagtha_original_file_name': OriginalFileName is ['mimikatz.exe'] (survives rename_image)
  - added 'yagtha_command_line': CommandLine contains all of ['privilege::debug', 'sekurlsa::logonpasswords'] (survives rename_image)

Improved rule:

title: Mimikatz Execution by Image Name (improved by YAGTHA)
id: 09d45394-2e6f-5b6a-a757-458fac4539c4
status: experimental
description: Derived by YAGTHA from rule 6a1f3c52-2b7e-4d8a-9c41-0e5b7f2d9a13. Adds selections on evidence
  that stayed the same in the variants that evaded the original rule.
author: Hoor Fawaz
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: \mimikatz.exe
  yagtha_original_file_name:
    OriginalFileName:
    - mimikatz.exe
  yagtha_command_line:
    CommandLine|contains|all:
    - privilege::debug
    - sekurlsa::logonpasswords
  condition: (selection) or (yagtha_original_file_name or yagtha_command_line)
level: high
related:
- id: 6a1f3c52-2b7e-4d8a-9c41-0e5b7f2d9a13
  type: derived

Verification:
  variants evading: 1 -> 0
    fixed      event0/rename_image
  regressions: none
  benign events matched: 0 -> 0 (of 14)
  regression cases: 19 (5 match, 14 no_match)

Result: PASSED
```

YAGTHA only adds values it found in the events, never guessed ones. The improved
rule is checked on all variants again and on normal activity
(`data/benign_events/benign.json`): it passes only if nothing the original caught
is lost and no new benign event triggers it. What it gets right is kept as
regression cases. Options: `--events`, `--benign`, `--mutations`, `--json`.

## Mutations

Each mutation keeps the attacker's behaviour and changes one detail they control.
Every mutation is a pure, deterministic function: the original event is never modified.

| Mutation | What changes |
| --- | --- |
| `rename_image` | Executable renamed (`OriginalFileName` still shows the real tool) |
| `change_path` | Same executable run from another folder |
| `change_case` | Mixed upper/lower case in file name and command line |
| `reorder_args` | Leading switches in a different order |
| `encode_cmdline` | PowerShell plain command vs `-EncodedCommand` |
| `add_noise_args` | A harmless extra switch (`-NoLogo`, `/d`) |
| `alt_parent` | A different parent process |

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
