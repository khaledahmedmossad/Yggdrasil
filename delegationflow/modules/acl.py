"""Read-only DACL inspection for one target object and one principal."""
from __future__ import annotations

from typing import Any

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.uuid import bin_to_string
from ldap3.utils.conv import escape_filter_chars

from delegationflow.core.exceptions import DirectorySearchError

# Active Directory access-mask values
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

# AD DS rights commonly used by the DS_GENERIC_WRITE mapping
ADS_RIGHT_DS_SELF = 0x00000008
ADS_RIGHT_DS_WRITE_PROP = 0x00000020

ACCESS_ALLOWED_ACE = 0x00
ACCESS_ALLOWED_OBJECT_ACE = 0x05
INHERITED_ACE = 0x10

ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02


def _classify_rights(mask: int, object_specific: bool) -> list[str]:
    rights = []
    if mask & GENERIC_ALL:
        rights.append("GenericAll")
    if mask & GENERIC_WRITE:
        rights.append("GenericWrite")
    # A broad DS write mapping: WriteProperty + Self, without an
    # object-specific attribute/property GUID restriction.
    if (
        not object_specific
        and (mask & (ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_DS_SELF))
        == (ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_DS_SELF)
    ):
        rights.append("GenericWrite")
    if mask & WRITE_DACL:
        rights.append("WriteDacl")
    if mask & WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & ADS_RIGHT_DS_WRITE_PROP:
        rights.append("WriteProperty")
    if mask & ADS_RIGHT_DS_SELF:
        rights.append("Self")
    return list(dict.fromkeys(rights))


def _format_guid(raw: bytes | bytearray | None) -> str | None:
    if not raw:
        return None
    if len(raw) != 16:
        return None
    return bin_to_string(bytes(raw)).lower()


def _parse_dacl(descriptor_bytes: bytes) -> tuple[Any, bool]:
    try:
        descriptor = SR_SECURITY_DESCRIPTOR(data=bytes(descriptor_bytes))
    except Exception as exc:
        raise DirectorySearchError(f"Could not parse the security descriptor: {exc}") from exc
    try:
        dacl = descriptor["Dacl"]
    except KeyError:
        dacl = b""
    present = bool(dacl)
    return dacl, present


def audit_target_acl(
    client,
    base_dn: str,
    target: str,
    principal: str,
) -> dict[str, Any]:
    """Read the target's DACL and collect allow ACEs matching the principal SID."""
    target = target.strip()
    principal = principal.strip()
    if not target or not principal:
        raise DirectorySearchError("Target and principal must not be empty.")

    target_filter = f"(sAMAccountName={escape_filter_chars(target)})"
    principal_filter = f"(sAMAccountName={escape_filter_chars(principal)})"

    principal_sid = client.lookup_sid(base_dn, principal_filter)
    target_record = client.read_security_descriptor(base_dn, target_filter)

    dacl, dacl_present = _parse_dacl(target_record["descriptor"])
    aces = list(getattr(dacl, "aces", [])) if dacl_present else []

    matches: list[dict[str, Any]] = []
    for ace in aces:
        ace_type = int(ace["AceType"])
        if ace_type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
            continue

        body = ace["Ace"]
        try:
            ace_sid = body["Sid"].formatCanonical()
        except (AttributeError, KeyError, TypeError):
            continue
        if ace_sid != principal_sid:
            continue

        mask = int(body["Mask"]["Mask"])
        ace_flags = int(ace["AceFlags"])
        object_guid = None
        inherited_object_guid = None
        object_specific = False

        if ace_type == ACCESS_ALLOWED_OBJECT_ACE:
            object_flags = int(body["Flags"])
            if object_flags & ACE_OBJECT_TYPE_PRESENT:
                object_guid = _format_guid(body["ObjectType"])
                object_specific = object_guid is not None
            if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                inherited_object_guid = _format_guid(body["InheritedObjectType"])

        matches.append({
            "ace_type": (
                "ACCESS_ALLOWED_OBJECT_ACE"
                if ace_type == ACCESS_ALLOWED_OBJECT_ACE
                else "ACCESS_ALLOWED_ACE"
            ),
            "inherited": bool(ace_flags & INHERITED_ACE),
            "access_mask": f"0x{mask:08X}",
            "rights": _classify_rights(mask, object_specific),
            "object_type": object_guid,
            "inherited_object_type": inherited_object_guid,
        })

    rights = sorted({right for match in matches for right in match["rights"]})
    inherited_rights = sorted({
        right
        for match in matches
        if match["inherited"]
        for right in match["rights"]
    })

    return {
        "target": {
            "dn": target_record["dn"],
            "sam_account_name": target_record["sam_account_name"],
            "object_sid": target_record["object_sid"],
        },
        "principal": {
            "sam_account_name": principal,
            "object_sid": principal_sid,
        },
        "dacl_present": dacl_present,
        "dacl_ace_count": len(aces),
        "matching_allow_aces": matches,
        "rights": rights,
        "inherited_rights": inherited_rights,
        "note": (
            "Allow ACEs grant the principal the listed rights in the target DACL; "
            "this does not by itself prove an exploitable path. Deny ACEs, group "
            "membership expansion, parent-object inheritance, and effective access "
            "were not evaluated. Object-specific WriteProperty ACEs are reported "
            "with their ObjectType GUID and are not mapped to GenericWrite."
        ),
    }
