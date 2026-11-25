from delegationflow.core.models import AssessmentResult, DirectoryAccount, Finding, Severity


def assess_accounts(server: str, base_dn: str,
                    accounts: list[DirectoryAccount]) -> AssessmentResult:
    findings: list[Finding] = []
    for index, account in enumerate(accounts, start=1):
        findings.append(Finding(
            finding_id=f"DF-UD-{index:04d}",
            title="Unconstrained Delegation enabled",
            severity=Severity.HIGH if account.enabled is not False else Severity.MEDIUM,
            status="confirmed_configuration",
            description=(
                "The directory object has the TRUSTED_FOR_DELEGATION userAccountControl flag. "
                "This is a confirmed configuration observation, not proof of an exploitable attack path."
            ),
            evidence={
                "distinguished_name": account.dn,
                "sam_account_name": account.sam_account_name,
                "enabled": account.enabled,
                "user_account_control": account.user_account_control,
                "service_principal_names": account.service_principal_names,
            },
            recommendations=[
                "Review whether unconstrained delegation is operationally required.",
                "Prefer constrained delegation or resource-based constrained delegation where appropriate.",
                "Mark sensitive accounts as non-delegable and review Protected Users eligibility.",
                "Monitor changes to delegation-related account attributes.",
            ],
        ))
        if account.service_principal_names:
            findings.append(Finding(
                finding_id=f"DF-SPN-{index:04d}",
                title="SPNs present on delegation-enabled account",
                severity=Severity.MEDIUM,
                status="confirmed_configuration",
                description="The delegation-enabled object has one or more registered SPNs. Review whether each service registration is expected.",
                evidence={
                    "distinguished_name": account.dn,
                    "service_principal_names": account.service_principal_names,
                },
                recommendations=[
                    "Validate ownership and business need for each SPN.",
                    "Remove stale SPNs through an approved change process, not through this read-only tool.",
                ],
            ))
        else:
            findings.append(Finding(
                finding_id=f"DF-SPN-{index:04d}",
                title="No SPNs returned for delegation-enabled account",
                severity=Severity.INFO,
                status="confirmed_configuration",
                description="No servicePrincipalName values were returned for this object. This may be expected and is not automatically a vulnerability.",
                evidence={"distinguished_name": account.dn},
                recommendations=["Verify the object type and expected service configuration."],
            ))
    return AssessmentResult(
        server=server,
        base_dn=base_dn,
        accounts=accounts,
        findings=findings,
    )
