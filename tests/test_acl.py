import pytest

pytest.importorskip("impacket")

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin

from delegationflow.modules.acl import _classify_rights, audit_target_acl

PRINCIPAL_SID = "S-1-5-21-1-2-3-1104"
OTHER_SID = "S-1-5-21-1-2-3-500"


def _sid(value):
    sid = ldaptypes.LDAP_SID()
    sid.fromCanonical(value)
    return sid


def _allowed(mask, sid_value, flags=0):
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    body = ldaptypes.ACCESS_ALLOWED_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = _sid(sid_value)
    ace["Ace"] = body
    return ace


def _allowed_object(mask, sid_value, flags=0, object_type=b""):
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    body = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Flags"] = 0
    body["ObjectType"] = object_type
    body["InheritedObjectType"] = b""
    body["Sid"] = _sid(sid_value)
    ace["Ace"] = body
    return ace


def _descriptor(*aces):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OffsetOwner"] = 0
    sd["OffsetGroup"] = 0
    sd["OffsetSacl"] = 0
    sd["OffsetDacl"] = 0
    sd["Sacl"] = b""
    sd["OwnerSid"] = b""
    sd["GroupSid"] = b""
    sd["Dacl"] = ldaptypes.ACL()
    sd["Dacl"]["AclRevision"] = 4
    sd["Dacl"]["Sbz1"] = 0
    sd["Dacl"]["AceCount"] = 0
    sd["Dacl"]["Sbz2"] = 0
    sd["Dacl"]["Data"] = b""
    sd["Dacl"].aces = list(aces)
    return sd.getData()


class _FakeClient:
    def __init__(self, descriptor):
        self.descriptor = descriptor

    def lookup_sid(self, search_base, search_filter):
        return PRINCIPAL_SID

    def read_security_descriptor(self, search_base, search_filter):
        return {
            "dn": "CN=callum.dixon,CN=Users,DC=lab,DC=local",
            "sam_account_name": "callum.dixon",
            "object_sid": "S-1-5-21-1-2-3-1107",
            "descriptor": self.descriptor,
        }


def test_classify_rights_requires_broad_write_mapping_for_generic_write():
    assert _classify_rights(0x28, object_specific=False) == [
        "GenericWrite", "WriteProperty", "Self",
    ]
    assert _classify_rights(0x20, object_specific=True) == ["WriteProperty"]
    assert _classify_rights(0x00040000, object_specific=False) == ["WriteDacl"]
    assert _classify_rights(0x00080000, object_specific=False) == ["WriteOwner"]
    assert _classify_rights(0x10000000, object_specific=False) == ["GenericAll"]


def test_audit_matches_principal_sid_and_keeps_object_guid_distinct():
    descriptor = _descriptor(
        _allowed(0x28, PRINCIPAL_SID),
        _allowed_object(
            0x20,
            PRINCIPAL_SID,
            object_type=string_to_bin("bf967aba-0de6-11d0-a285-00aa003049e2"),
        ),
        _allowed(0x00040000, PRINCIPAL_SID, flags=0x10),
        _allowed(0x10000000, OTHER_SID),
    )
    report = audit_target_acl(
        _FakeClient(descriptor), "DC=lab,DC=local", "callum.dixon", "carole.rose"
    )

    assert report["dacl_ace_count"] == 4
    assert len(report["matching_allow_aces"]) == 3
    assert report["rights"] == ["GenericWrite", "Self", "WriteDacl", "WriteProperty"]
    assert report["inherited_rights"] == ["WriteDacl"]
    object_ace = report["matching_allow_aces"][1]
    assert object_ace["rights"] == ["WriteProperty"]
    assert object_ace["object_type"] == "bf967aba-0de6-11d0-a285-00aa003049e2"
