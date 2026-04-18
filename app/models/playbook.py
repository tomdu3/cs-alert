"""Pydantic models for incident-response playbooks."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.alert import ThreatCategory


class PlaybookStep(BaseModel):
    """A single actionable step within a playbook phase."""

    title: str
    description: str
    commands: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    responsible_role: str = "Security Analyst"


class PlaybookPhase(BaseModel):
    """One NIST IR phase (e.g. Containment) with its steps."""

    name: str  # e.g. "Identification"
    steps: list[PlaybookStep]


class Playbook(BaseModel):
    """Complete incident-response playbook."""

    id: str
    name: str
    threat_category: ThreatCategory
    description: str
    phases: list[PlaybookPhase]


class PlaybookRecommendation(BaseModel):
    """A playbook matched to a specific alert."""

    playbook: Playbook
    match_confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
