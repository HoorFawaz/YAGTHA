# Sample data

Everything here is **synthetic**. No real malware, no real logs, no real users.

- `rules/`: sample Sigma rules (Windows `process_creation`).
- `malicious_events/`: baseline events each rule should catch, one JSON list per rule.
- `benign_events/`: normal activity used to check for false positives (Phase 4).

Events use Sysmon-like field names (`Image`, `OriginalFileName`, `CommandLine`,
`ParentImage`, `User`, ...).
