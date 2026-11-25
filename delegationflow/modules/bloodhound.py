"""Offline, read-only correlation of BloodHound JSON node/ACL edge exports."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

WRITE_RELATIONS = {"GenericWrite", "GenericAll", "WriteDacl", "WriteOwner", "AddMember", "WriteSPN"}
DELEGATION_MARKERS = {"unconstraineddelegation", "allowedtodelegateto", "trustedfordelegation"}

def _is_delegation_node(node: dict[str, Any]) -> bool:
    props = node.get("props", {})
    if props.get("unconstraineddelegation") is True:
        return True
    if props.get("trustedfordelegation") is True:
        return True
    allowed = props.get("allowedtodelegateto") or props.get("msds-allowedtodelegateto")
    return bool(allowed)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def analyze_bloodhound_export(path: str) -> dict[str, Any]:
    """Analyze a directory containing BloodHound *_nodes.json and *_aces.json files.

    Supports common BloodHound JSON export shape (data: [...]). It does not
    infer missing edges or claim exploitability from a write edge alone.
    """
    root = Path(path).expanduser()
    if not root.is_dir():
        raise ValueError("BloodHound export path must be an extracted directory")
    node_files = list(root.glob("*_nodes.json")) + list(root.glob("*nodes*.json"))
    ace_files = list(root.glob("*_aces.json")) + list(root.glob("*aces*.json"))
    nodes: dict[str, dict[str, Any]] = {}
    for file in dict.fromkeys(node_files):
        payload = _load_json(file)
        for node in payload.get("data", []) if isinstance(payload, dict) else []:
            props = node.get("Properties", node.get("properties", {}))
            key = str(props.get("objectid", props.get("ObjectIdentifier", ""))).lower()
            if key: nodes[key] = {"props": props, "type": node.get("type", "unknown")}
    edges = []
    for file in dict.fromkeys(ace_files):
        payload = _load_json(file)
        for edge in payload.get("data", []) if isinstance(payload, dict) else []:
            props = edge.get("Properties", edge.get("properties", {}))
            relation = str(props.get("rightname", props.get("RightName", edge.get("label", ""))))
            source = str(edge.get("StartNode", edge.get("start", ""))).lower()
            target = str(edge.get("EndNode", edge.get("end", ""))).lower()
            if relation in WRITE_RELATIONS:
                src = nodes.get(source, {}).get("props", {}).get("name", source)
                dst = nodes.get(target, {}).get("props", {}).get("name", target)
                edges.append({"principal": src, "principal_id": source, "right": relation,
                              "target": dst, "target_id": target,
                              "target_is_delegation_account": _is_delegation_node(nodes.get(target, {}))})
    candidate_paths = [edge for edge in edges if edge["target_is_delegation_account"]]
    graph_lines = ["flowchart LR"]
    for index, edge in enumerate(candidate_paths, 1):
        principal = f"P{index}"
        target = f"T{index}"
        graph_lines.append(f'  {principal}["{edge["principal"]}"] -->|{edge["right"]}| {target}["{edge["target"]}"]')
    return {"source": str(root), "nodes_loaded": len(nodes), "write_edges": edges,
            "candidate_delegation_paths": candidate_paths,
            "mermaid_graph": "\n".join(graph_lines),
            "note": "ACL edges are evidence of directory rights in the supplied export; validate object state, inheritance, and effective access in the live directory."}
