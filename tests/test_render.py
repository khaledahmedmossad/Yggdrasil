from delegationflow.modules.assessment import assess_accounts


def test_result_json_serializes():
    result = assess_accounts("dc.inlanefreight.local", "DC=example,DC=local", [])
    payload = result.model_dump_json()
    assert '"server":"dc.inlanefreight.local"' in payload
    assert '"findings":[]' in payload
