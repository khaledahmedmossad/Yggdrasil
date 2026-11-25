import json
from typing import Any

from delegationflow.core.models import DirectoryAccount
from delegationflow.core.exceptions import DirectorySearchError
from delegationflow.integrations.ldap_client import LDAPDirectoryClient

# LDAP bitwise AND matching rule: 1.2.840.113556.1.4.803
# TRUSTED_FOR_DELEGATION = 0x80000 (524288)
UNCONSTRAINED_DELEGATION_FILTER = (
    "(&(|(objectCategory=person)(objectCategory=computer))"
    "(userAccountControl:1.2.840.113556.1.4.803:=524288))"
)
ATTRIBUTES = [
    "distinguishedName", "name", "sAMAccountName", "objectClass",
    "userAccountControl", "servicePrincipalName", "userAccountControl",
]


def _values_from_entry_json(entry_json: str) -> dict[str, Any]:
    try:
        parsed = json.loads(entry_json)
        return parsed.get("attributes", {})
    except (TypeError, json.JSONDecodeError):
        return {}


def _first(value, default=None):
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default


def _as_int(value):
    try:
        return int(_first(value))
    except (TypeError, ValueError):
        return None


def enumerate_unconstrained(client: LDAPDirectoryClient, base_dn: str,
                             page_size: int = 500) -> list[DirectoryAccount]:
    raw_entries = client.search_paged(
        base_dn, UNCONSTRAINED_DELEGATION_FILTER, ATTRIBUTES, page_size
    )
    accounts: list[DirectoryAccount] = []
    for raw in raw_entries:
        attrs = _values_from_entry_json(raw)
        dn = _first(attrs.get("distinguishedName")) or _first(attrs.get("entryDN"))
        if not dn:
            # entry_to_json includes the DN in the top-level dn field on ldap3 versions.
            try:
                dn = json.loads(raw).get("dn")
            except Exception:
                dn = None
        if not dn:
            continue
        uac = _as_int(attrs.get("userAccountControl"))
        classes = attrs.get("objectClass") or []
        if not isinstance(classes, list):
            classes = [classes]
        spns = attrs.get("servicePrincipalName") or []
        if not isinstance(spns, list):
            spns = [spns]
        sam = _first(attrs.get("sAMAccountName"))
        name = _first(attrs.get("name")) or sam or dn
        accounts.append(DirectoryAccount(
            dn=str(dn),
            name=str(name),
            sam_account_name=str(sam) if sam else None,
            object_classes=[str(x) for x in classes],
            user_account_control=uac,
            enabled=(not bool(uac & 0x2)) if uac is not None else None,
            service_principal_names=[str(x) for x in spns if x],
        ))
    return accounts
