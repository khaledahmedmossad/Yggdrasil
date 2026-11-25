import json
from delegationflow.modules.delegation_modes import _record


def test_record_extracts_delegation_attributes():
    raw = json.dumps({"dn": "CN=svc,DC=lab,DC=local", "attributes": {
        "name": "svc", "sAMAccountName": "svc", "userAccountControl": 524288,
        "objectClass": ["top", "person", "user"],
        "servicePrincipalName": ["HTTP/app.lab.local"],
        "msDS-AllowedToDelegateTo": ["MSSQLSvc/sql.lab.local"],
        "msDS-AllowedToActOnBehalfOfOtherIdentity": "AAECAw=="
    }})
    item = _record(raw)
    assert item["dn"] == "CN=svc,DC=lab,DC=local"
    assert item["enabled"] is True
    assert item["allowed_to_delegate_to"] == ["MSSQLSvc/sql.lab.local"]
    assert item["rbcd_descriptor_present"] is True
