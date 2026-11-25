# Security Notes

DelegationFlow's assessment commands are designed as a read-only utility. The separate `exploit` command is an opt-in, write-capable authorized-lab workflow that needs inbound TCP 445 reachable from the target.

- Use it only against domains you own or are explicitly authorized to assess.
- Use a least-privileged account with directory read permissions.
- Prefer LDAPS with certificate validation where supported.
- Do not place passwords in YAML files, command-line arguments, shell history, or issue reports.
- JSON output contains directory metadata and should be handled as potentially sensitive.
- The read-only assessment commands do not perform exploitation or modify directory objects.
- The `exploit` command performs DNS/SPN writes, coercion, ticket capture, DCSync, and remote file reads; use it only in an authorized lab and prefer `--cleanup`.

Report security issues privately to the project maintainer before public disclosure.
