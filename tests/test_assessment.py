from delegationflow.core.models import DirectoryAccount, Severity
from delegationflow.modules.assessment import assess_accounts


def test_assessment_flags_unconstrained_and_spn():
    account = DirectoryAccount(
        dn="CN=svc,OU=Service Accounts,DC=example,DC=local",
        name="svc",
        sam_account_name="svc",
        user_account_control=524288,
        enabled=True,
        service_principal_names=["HTTP/app.inlanefreight.local"],
    )
    result = assess_accounts("dc.inlanefreight.local", "DC=example,DC=local", [account])
    assert len(result.findings) == 2
    assert result.findings[0].severity == Severity.HIGH
    assert result.findings[1].title.startswith("SPNs present")


def test_empty_assessment():
    result = assess_accounts("dc.inlanefreight.local", "DC=example,DC=local", [])
    assert result.accounts == []
    assert result.findings == []
