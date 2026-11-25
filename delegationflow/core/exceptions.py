class DelegationFlowError(Exception):
    """Base application error."""


class ConfigurationError(DelegationFlowError):
    """Invalid or incomplete configuration."""


class DirectoryConnectionError(DelegationFlowError):
    """LDAP connection or bind failed."""


class DirectorySearchError(DelegationFlowError):
    """LDAP search failed or returned an unsuccessful result."""
