"""Pydantic models for security alerts."""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field


class ThreatCategory(str, enum.Enum):
    """Categorisation of the detected threat."""

    SQL_INJECTION = "sql_injection"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    """Threat severity level (NIST-aligned)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(str, enum.Enum):
    """Current status of the alert."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


# ── Inbound payload ─────────────────────────────────────────────
class AlertCreate(BaseModel):
    """Schema for submitting a new alert to the API."""

    source_ip: str = Field(..., examples=["192.168.1.105"])
    event_type: str = Field(..., examples=["web_request", "email", "auth_attempt"])
    raw_log: str = Field(
        ...,
        examples=[
            "GET /login?user=admin'%20OR%201=1-- HTTP/1.1 200 3122"
        ],
    )
    target_system: str = Field(..., examples=["web-server-01"])
    timestamp: datetime | None = None


# ── Enriched alert (after threat engine) ────────────────────────
class Alert(BaseModel):
    """Fully enriched alert returned by the API."""

    id: str
    source_ip: str
    event_type: str
    raw_log: str
    target_system: str
    timestamp: datetime
    threat_category: ThreatCategory
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    status: AlertStatus = AlertStatus.NEW
    matched_playbook_id: str | None = None
    analysis_reasoning: str = ""


# ── Lightweight list view ───────────────────────────────────────
class AlertSummary(BaseModel):
    """Light projection used in dashboard list views."""

    id: str
    source_ip: str
    event_type: str
    target_system: str
    timestamp: datetime
    threat_category: ThreatCategory
    severity: Severity
    confidence: float
    status: AlertStatus
