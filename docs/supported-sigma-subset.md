# Supported Sigma subset

YAGTHA has its own small Sigma evaluator. It supports the subset below and
raises `UnsupportedRuleFeatureError` for anything else, so a rule is never
evaluated with part of its logic silently ignored.

## Rules

| Key | Support |
| --- | --- |
| `title` | Required. |
| `id` | Optional. Without it, an id is built from the title. |
| `logsource` | Must be `category: process_creation` and `product: windows`. |
| `level` | Optional: `informational`, `low`, `medium` (default), `high`, `critical`. |
| `description`, `status`, `author`, `references`, `tags`, ... | Kept as data, not used. |
| `detection` | Required. See below. |

## Selections

- A selection is a **map** of `Field|modifiers: value` entries (all must match, AND),
  or a **list of maps** (any map may match, OR).
- A value can be a single value or a **list** (any value may match, OR).
- Values can be strings, numbers, booleans or `null`. `null` matches a missing or empty field.
- Keyword lists (strings without a field name) are **not supported**.

## Modifiers

| Modifier | Meaning |
| --- | --- |
| *(none)* | Whole value matches, wildcards allowed. |
| `contains` | Value appears anywhere. |
| `startswith` | Field starts with the value. |
| `endswith` | Field ends with the value. |
| `all` | With a list: every value must match (AND instead of OR). |
| `re` | Regular expression search (case-sensitive, like Sigma). |

Only one of `contains`, `startswith`, `endswith`, `re` per field. `all` can be
combined with any of them. Every other modifier (`base64offset`, `windash`,
`cidr`, `expand`, ...) is **not supported**.

## String matching

- Case-insensitive, like Sigma.
- `*` matches any sequence, `?` matches one character.
- `\*`, `\?` and `\\` are escapes for a literal `*`, `?` and `\`. Any other
  backslash is literal, so `'\mimikatz.exe'` means a backslash followed by `mimikatz.exe`.
- Wildcards are matched without regex and without exponential backtracking.

## Regex safety

- At most 512 characters per pattern.
- Nested quantifiers such as `(a+)+` are rejected.
- Each search has a 0.25 s time limit; a timeout raises `RuleEvaluationError`.

## Condition

| Syntax | Support |
| --- | --- |
| `selection` | Yes |
| `and`, `or`, `not`, parentheses | Yes (`not` binds tighter than `and`, `and` tighter than `or`) |
| `1 of selection_*`, `all of selection_*` | Yes |
| `1 of them`, `all of them` | Yes (selections starting with `_` are skipped) |
| A list of conditions | Yes (combined with `or`) |
| `N of ...` with N other than 1 | No |
| Aggregations (`\| count() > 5`, `\| near`) | No |
| `timeframe` | No |

## Limits

Rule files up to 256 KB, 64 selections, 256 values per field, condition up to
2,000 characters and 32 levels of nesting, event field values up to 32,768
characters.
