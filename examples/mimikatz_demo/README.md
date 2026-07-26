# Mimikatz demo

Real output of:

```bash
yagtha run --rule data/rules/mimikatz.yml --out output/
```

| File | What it is |
| --- | --- |
| [`original_rule.yml`](original_rule.yml) | The fragile rule: `Image\|endswith '\mimikatz.exe'` only |
| [`improved_rule.yml`](improved_rule.yml) | The rule YAGTHA proposed and verified |
| [`report.md`](report.md) | Full report: evasions, changes, verification, every variant |
| [`regression_cases.json`](regression_cases.json) | 19 cases: 5 variants that must match, 14 benign events that must not |
| [`test_regression.py`](test_regression.py) | Runs those cases against the improved rule |

Re-check the improved rule from this folder:

```bash
pytest
```

A test in `tests/test_samples.py` runs the command again and checks that these
files are exactly what YAGTHA produces, so the demo cannot drift from the code.
