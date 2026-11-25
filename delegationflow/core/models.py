from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DirectoryAccount(BaseModel):
    dn: str
    name: str = "Unknown"
    sam_account_name: str | None = None
    object_classes: list[str] = Field(default_factory=list)
    user_account_control: int | None = None
    enabled: bool | None = None
    service_principal_names: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    status: str = "confirmed_configuration"
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)


class AssessmentResult(BaseModel):
    tool: str = "DelegationFlow"
    version: str = "0.3.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    server: str
    base_dn: str
    accounts: list[DirectoryAccount] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    @property
    def finding_counts(self) -> dict[str, int]:
        return {severity.value: sum(1 for f in self.findings if f.severity == severity)
                for severity in Severity}
