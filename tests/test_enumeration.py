import json
from delegationflow.modules.enumeration import enumerate_unconstrained, UNCONSTRAINED_DELEGATION_FILTER


class FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.called = False

    def search_paged(self, base, search_filter, attributes, page_size):
        self.called = True
        assert search_filter == UNCONSTRAINED_DELEGATION_FILTER
        return self.rows


def test_enumerates_account_from_ldap_json():
    row = {
        "dn": "CN=svc,DC=example,DC=local",
        "attributes": {
            "name": "svc",
            "sAMAccountName": "svc",
            "objectClass": ["top", "person", "user"],
            "userAccountControl": 524288,
            "servicePrincipalName": ["HTTP/app.inlanefreight.local"],
        },
    }
    client = FakeClient([json.dumps(row)])
    accounts = enumerate_unconstrained(client, "DC=example,DC=local")
    assert client.called
    assert len(accounts) == 1
    assert accounts[0].name == "svc"
    assert accounts[0].enabled is True
    assert accounts[0].service_principal_names == ["HTTP/app.inlanefreight.local"]
