"""Enterprise context models for RedEye.

RedEye's own structures for enterprise-grade scanning, built around the
standard enterprise concepts -- a CMDB asset row, a CVE advisory, a required
security control, and GitHub Enterprise repo metadata. They are file-first
and backend-agnostic so a scan can be enriched entirely offline; live API
connectors (e.g. GitHub Enterprise) layer on top of these same models.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class AssetCriticality(str, enum.Enum):
    """How important the asset is to the business. Drives finding priority."""

    CROWN_JEWEL = "crown_jewel"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def severity_boost(self) -> int:
        """Notches to bump a finding's severity for assets of this criticality."""
        return {
            AssetCriticality.CROWN_JEWEL: 2,
            AssetCriticality.HIGH: 1,
            AssetCriticality.MEDIUM: 0,
            AssetCriticality.LOW: 0,
            AssetCriticality.UNKNOWN: 0,
        }[self]


class DataClassification(str, enum.Enum):
    """Sensitivity of the data the asset handles."""

    PCI = "pci"
    PII = "pii"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class CmdbRecord(BaseModel):
    """One configuration-management-database row for an application/service."""

    application_id: str = Field(..., description="Stable external AppId (CMDB key).")
    name: str = Field(default="", description="Human-readable service name.")
    owner: str = Field(default="", description="Owning team or individual.")
    business_unit: str = Field(default="", description="Org / business unit.")
    environment: str = Field(default="production", description="production | staging | dev")
    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    data_classification: list[DataClassification] = Field(default_factory=list)
    repos: list[str] = Field(
        default_factory=list, description="Repo slugs or URLs this application owns."
    )
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class CveRecord(BaseModel):
    """A known vulnerability advisory relevant to a scan target."""

    cve_id: str = Field(..., description="e.g. CVE-2024-1234")
    cwe: str | None = Field(default=None, description="Associated CWE, e.g. CWE-79.")
    severity: str = Field(default="", description="critical | high | medium | low")
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    components: list[str] = Field(
        default_factory=list, description="Affected packages / components."
    )
    summary: str = Field(default="", max_length=2000)
    references: list[str] = Field(default_factory=list)


class ControlRecord(BaseModel):
    """A required security control the target is expected to satisfy."""

    control_id: str = Field(..., description="e.g. NIST-AC-3, PCI-6.5.1, ASVS-5.3.4")
    title: str = Field(default="")
    description: str = Field(default="", max_length=2000)
    cwe: list[str] = Field(default_factory=list, description="CWE families this control mitigates.")
    required: bool = True


class EnterpriseContext(BaseModel):
    """The enterprise enrichment bundle attached to a single scan target.

    Assembled by :mod:`redeye.enterprise.loader` and (optionally) the GitHub
    Enterprise connector, then threaded into the pipeline so stages can
    prioritise by asset criticality and correlate findings to known CVEs /
    required controls.
    """

    cmdb: CmdbRecord | None = None
    cves: list[CveRecord] = Field(default_factory=list)
    controls: list[ControlRecord] = Field(default_factory=list)
    github_enterprise: dict[str, Any] = Field(
        default_factory=dict, description="GHE repo metadata (filled by the connector)."
    )

    def cves_for_cwe(self, cwe: str | None) -> list[CveRecord]:
        """All known CVEs whose CWE matches ``cwe`` (case-insensitive)."""
        if not cwe:
            return []
        target = cwe.upper()
        return [c for c in self.cves if c.cwe and c.cwe.upper() == target]

    def controls_for_cwe(self, cwe: str | None) -> list[ControlRecord]:
        """All controls that mitigate ``cwe`` (case-insensitive)."""
        if not cwe:
            return []
        target = cwe.upper()
        return [c for c in self.controls if any(x.upper() == target for x in c.cwe)]

    @property
    def is_empty(self) -> bool:
        return not (self.cmdb or self.cves or self.controls or self.github_enterprise)
