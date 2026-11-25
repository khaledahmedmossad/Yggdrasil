# Expanded Feature Guide (0.3.0)

## LDAP full audit

`delegationflow full-audit` performs read-only LDAP searches for:

- Unconstrained delegation (`TRUSTED_FOR_DELEGATION`)
- Constrained delegation (`msDS-AllowedToDelegateTo`)
- RBCD descriptor presence (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
- Domain controllers (`SERVER_TRUST_ACCOUNT` UAC bit)
- The direct members returned for the `Protected Users` group

The report records configuration and context. It does not determine effective access, recursively expand nested group membership, or prove an attack path.

## Offline BloodHound ACL analysis

`delegationflow bloodhound --directory <directory>` reads extracted `*_nodes.json` and `*_aces.json` files. It reports write-capable relationships such as GenericWrite, GenericAll, WriteDacl, WriteOwner, AddMember, and WriteSPN, including whether the target node's exported properties indicate a delegation configuration. Candidate edges targeting delegation-enabled nodes are correlated and can be exported as a Mermaid graph with `--graph paths.mmd`.

This is an offline correlation aid. BloodHound export formats vary by version; verify that the export contains the expected nodes and ACL edges. Validate inheritance, object state, and effective permissions in the live directory before treating an edge as actionable.

## Reports

- `assess --output result.json --html result.html`
- `full-audit --output result.json --html result.html`

HTML reports are self-contained and escape directory-derived text before rendering.

## Authorized-lab exploit workflow (0.3.0)

`delegationflow exploit` is an opt-in command for the authorized Kerberos
delegation lab. It:

- confirms the target account advertises `TRUSTED_FOR_DELEGATION`;
- creates an ADIDNS A record for the attacker host;
- adds a matching `CIFS/<host>` SPN to the unconstrained-delegation account
  using the GenericWrite principal;
- starts a minimal SMB ticket catcher on port 445;
- coerces the DC through MS-RPRN (with an MS-EFSRPC fallback);
- extracts the forwarded TGT and DCSyncs `Administrator`;
- reads the requested remote file over SMB;
- with `--cleanup`, removes the SPN and DNS record created by the run.

This command performs write operations and network coercion. Keep the read-only
assessment commands and the exploit command separate in reporting and use the
exploit command only against systems you are explicitly authorized to test.

## Read-only exclusions

The `check`, `enumerate`, `assess`, `full-audit`, `bloodhound`, and `acl`
commands do not create DNS records, modify SPNs, change delegation settings,
coerce authentication, capture or extract tickets, dump credentials, or perform
DCSync.
