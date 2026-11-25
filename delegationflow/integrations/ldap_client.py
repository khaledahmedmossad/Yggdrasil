import logging
import ssl
from typing import Any

from ldap3 import ALL, BASE, LEVEL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.microsoft import security_descriptor_control

from delegationflow.core.exceptions import DirectoryConnectionError, DirectorySearchError

log = logging.getLogger(__name__)


class LDAPDirectoryClient:
    """Small read-only LDAP client. No modify/add/delete operations are exposed."""

    def __init__(self, settings, password: str):
        self.settings = settings
        self.password = password
        self.server = None
        self.connection = None

    def connect(self) -> None:
        try:
            tls = None
            if self.settings.use_ssl:
                tls = Tls(validate=ssl.CERT_REQUIRED if self.settings.validate_tls else ssl.CERT_NONE)
            self.server = Server(
                self.settings.server,
                port=self.settings.port,
                use_ssl=self.settings.use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=self.settings.connect_timeout,
            )
            self.connection = Connection(
                self.server,
                user=self.settings.username,
                password=self.password,
                auto_bind=True,
                receive_timeout=self.settings.receive_timeout,
                read_only=True,
                raise_exceptions=False,
            )
            if not self.connection.bound:
                result = self.connection.result or {}
                description = result.get("description", "LDAP bind failed")
                code = result.get("result", "unknown")
                raise DirectoryConnectionError(f"LDAP bind failed ({code}): {description}")
        except DirectoryConnectionError:
            raise
        except (LDAPException, OSError, ssl.SSLError) as exc:
            raise DirectoryConnectionError(f"Could not connect or bind to LDAP server: {exc}") from exc

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.unbind()
            except Exception:
                log.debug("LDAP unbind encountered an error.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def search_paged(self, search_base: str, search_filter: str,
                     attributes: list[str], page_size: int = 500) -> list[dict[str, Any]]:
        if self.connection is None or not self.connection.bound:
            raise DirectorySearchError("LDAP connection is not bound.")
        entries: list[dict[str, Any]] = []
        cookie = None
        try:
            while True:
                ok = self.connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
                result = self.connection.result or {}
                if not ok and result.get("result", 0) != 0:
                    code = result.get("result", "unknown")
                    description = result.get("message") or result.get("description") or "LDAP search failed"
                    raise DirectorySearchError(f"LDAP search failed ({code}): {description}")
                for entry in self.connection.entries:
                    entries.append(entry.entry_to_json())  # parsed below; preserves values safely
                controls = result.get("controls", {})
                paging = controls.get("1.2.840.113556.1.4.319", {})
                cookie = paging.get("value", {}).get("cookie")
                if not cookie:
                    break
        except DirectorySearchError:
            raise
        except (LDAPException, OSError) as exc:
            raise DirectorySearchError(f"LDAP search error: {exc}") from exc
        return entries

    def lookup_sid(self, search_base: str, search_filter: str) -> str:
        """Resolve exactly one directory object's objectSid."""
        if self.connection is None or not self.connection.bound:
            raise DirectorySearchError("LDAP connection is not bound.")
        try:
            ok = self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["objectSid"],
                size_limit=2,
            )
            result = self.connection.result or {}
            if not ok and result.get("result", 0) != 0:
                raise DirectorySearchError(
                    f"SID lookup failed: {result.get('message') or result.get('description')}"
                )
            if len(self.connection.entries) != 1:
                raise DirectorySearchError(
                    f"Expected one object for SID lookup, found {len(self.connection.entries)}."
                )
            sid = self.connection.entries[0].objectSid.value
            if not sid:
                raise DirectorySearchError("The requested object has no readable objectSid.")
            return str(sid)
        except DirectorySearchError:
            raise
        except (LDAPException, OSError, AttributeError) as exc:
            raise DirectorySearchError(f"SID lookup error: {exc}") from exc

    def read_security_descriptor(self, search_base: str, search_filter: str) -> dict:
        """Read one object's DACL using the LDAP Security Descriptor control."""
        if self.connection is None or not self.connection.bound:
            raise DirectorySearchError("LDAP connection is not bound.")
        try:
            ok = self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "objectSid", "nTSecurityDescriptor"],
                controls=security_descriptor_control(sdflags=0x04),
                size_limit=2,
            )
            result = self.connection.result or {}
            if not ok and result.get("result", 0) != 0:
                raise DirectorySearchError(
                    "DACL query failed "
                    f"({result.get('result')}): "
                    f"{result.get('message') or result.get('description')}"
                )
            if len(self.connection.entries) != 1:
                raise DirectorySearchError(
                    f"Expected one target object, found {len(self.connection.entries)}."
                )
            entry = self.connection.entries[0]
            raw_attributes = entry.entry_raw_attributes
            descriptor_values = raw_attributes.get("nTSecurityDescriptor", [])
            if not descriptor_values:
                raise DirectorySearchError(
                    "The server returned no nTSecurityDescriptor. "
                    "The bind account may not have permission to read the DACL."
                )
            return {
                "dn": entry.entry_dn,
                "sam_account_name": str(entry.sAMAccountName.value or ""),
                "object_sid": str(entry.objectSid.value or ""),
                "descriptor": descriptor_values[0],
            }
        except DirectorySearchError:
            raise
        except (LDAPException, OSError, AttributeError, KeyError) as exc:
            raise DirectorySearchError(f"Security descriptor read error: {exc}") from exc
