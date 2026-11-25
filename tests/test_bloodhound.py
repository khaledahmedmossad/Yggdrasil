import json
from delegationflow.modules.bloodhound import analyze_bloodhound_export


def test_bloodhound_write_edge(tmp_path):
    (tmp_path / "users_nodes.json").write_text(json.dumps({"data": [
        {"type": "User", "Properties": {"objectid": "S-1-5-21-1", "name": "analyst@LAB.LOCAL"}},
        {"type": "Computer", "Properties": {"objectid": "S-1-5-21-2", "name": "SQL01.LAB.LOCAL", "unconstraineddelegation": True}},
    ]}))
    (tmp_path / "users_aces.json").write_text(json.dumps({"data": [
        {"StartNode": "S-1-5-21-1", "EndNode": "S-1-5-21-2", "Properties": {"rightname": "GenericWrite"}}
    ]}))
    result = analyze_bloodhound_export(str(tmp_path))
    assert result["nodes_loaded"] == 2
    assert result["write_edges"][0]["right"] == "GenericWrite"
    assert result["write_edges"][0]["principal"] == "analyst@LAB.LOCAL"
    assert len(result["candidate_delegation_paths"]) == 1
    assert "GenericWrite" in result["mermaid_graph"]
