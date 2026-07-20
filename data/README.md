# Sample data

Everything here is **synthetic**. No real malware, no real logs, no real users.

- `rules/`: sample Sigma rules (Windows `process_creation`).
- `malicious_events/`: baseline events each rule should catch, one JSON list per rule.
- `benign_events/benign.json`: 14 synthetic normal-activity events (browsers, admin
  PowerShell, `certutil -hashfile`, notepad opening notes about mimikatz...) used to
  check improved rules for false positives.

Events use Sysmon-like field names (`Image`, `OriginalFileName`, `CommandLine`,
`ParentImage`, `User`, ...).
