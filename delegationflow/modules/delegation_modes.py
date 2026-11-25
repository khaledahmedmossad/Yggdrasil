"""Read-only discovery for constrained and resource-based delegation."""
from __future__ import annotations
import json
from typing import Any

from delegationflow.core.exceptions import DirectorySearchError

UAC_UNCONSTRAINED = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
UAC_DC = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"


def _attrs(raw: str) -> dict[str, Any]:
    try:
        return json.loads(raw).get("attributes", {})
    except (TypeError, json.JSONDecodeError):
        return {}


def _one(v, default=None):
    return v[0] if isinstance(v, list) and v else (v if v is not None else default)


def _list(v):
    if v is None: return []
    return v if isinstance(v, list) else [v]


def _record(raw: str) -> dict[str, Any] | None:
    data = _attrs(raw)
    try: dn = _one(data.get("distinguishedName")) or json.loads(raw).get("dn")
    except Exception: dn = _one(data.get("distinguishedName"))
    if not dn: return None
    uac = _one(data.get("userAccountControl"))
    try: uac = int(uac) if uac is not None else None
    except (TypeError, ValueError): uac = None
    return {
        "dn": str(dn), "name": str(_one(data.get("name"), dn)),
        "sam_account_name": _one(data.get("sAMAccountName")),
        "object_classes": [str(x) for x in _list(data.get("objectClass"))],
        "enabled": (not bool(uac & 2)) if uac is not None else None,
        "uac": uac,
        "spns": [str(x) for x in _list(data.get("servicePrincipalName")) if x],
        "allowed_to_delegate_to": [str(x) for x in _list(data.get("msDS-AllowedToDelegateTo")) if x],
        "rbcd_descriptor_present": bool(_list(data.get("msDS-AllowedToActOnBehalfOfOtherIdentity"))),
    }


def enumerate_delegation_modes(client, base_dn: str, page_size: int = 500) -> dict[str, list[dict[str, Any]]]:
    attrs = ["distinguishedName", "name", "sAMAccountName", "objectClass", "userAccountControl",
             "servicePrincipalName", "msDS-AllowedToDelegateTo",
             "msDS-AllowedToActOnBehalfOfOtherIdentity"]
    filters = {
        "unconstrained": f"(&(|(objectCategory=person)(objectCategory=computer)){UAC_UNCONSTRAINED})",
        "constrained": "(msDS-AllowedToDelegateTo=*)",
        "rbcd": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
    }
    output = {}
    for mode, ldap_filter in filters.items():
        records = client.search_paged(base_dn, ldap_filter, attrs, page_size)
        output[mode] = [r for raw in records if (r := _record(raw))]
    return output


def enumerate_domain_controllers(client, base_dn: str, page_size: int = 500) -> list[dict[str, Any]]:
    attrs = ["distinguishedName", "name", "sAMAccountName", "userAccountControl", "dNSHostName", "operatingSystem"]
    raw = client.search_paged(base_dn, f"(&(objectCategory=computer){UAC_DC})", attrs, page_size)
    records = []
    for item in raw:
        r = _record(item)
        if r:
            a = _attrs(item)
            r["dns_hostname"] = _one(a.get("dNSHostName"))
            r["operating_system"] = _one(a.get("operatingSystem"))
            records.append(r)
    return records


def enumerate_protected_users_group(client, base_dn: str, page_size: int = 500) -> dict[str, Any]:
    raw = client.search_paged(base_dn, "(&(objectCategory=group)(cn=Protected Users))", ["distinguishedName", "cn", "member"], page_size)
    if not raw:
        return {"group_found": False, "members": []}
    a = _attrs(raw[0])
    return {"group_found": True, "group_dn": _one(a.get("distinguishedName")),
            "members": [str(x) for x in _list(a.get("member")) if x]}
