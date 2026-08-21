"""Agent state schemas and structured output models.

Defines the canonical ``AgentState`` TypedDict that flows through the
LangGraph supervisor graph, plus Pydantic models for structured LLM outputs
(threat indicators, mitigation actions, triage results).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

# ═══════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════


class Severity(StrEnum):
    """Alert severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentName(StrEnum):
    """Named agents in the supervisor graph."""

    SUPERVISOR = "supervisor"
    TRIAGE = "triage"
    INTEL_RETRIEVAL = "intel_retrieval"
    MITIGATION = "mitigation"


class PipelineStatus(StrEnum):
    """High-level pipeline execution status."""

    PENDING = "pending"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    COMPLETE = "complete"
    ERROR = "error"


# ═══════════════════════════════════════════════════════════════
#  Pydantic Structured Output Models
# ═══════════════════════════════════════════════════════════════


class ThreatIndicator(BaseModel):
    """A single Indicator of Compromise (IoC) extracted from telemetry."""

    indicator_type: str = Field(
        ...,
        description="Type of indicator: ip, domain, hash, cve, email, url",
    )
    value: str = Field(
        ..., description="The indicator value (e.g., '192.168.1.100', 'CVE-2024-1234')"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score from 0.0 to 1.0",
    )
    context: str = Field(default="", description="Surrounding context or provenance")
    first_seen: datetime | None = Field(
        default=None, description="When the indicator was first observed"
    )


class MitigationAction(BaseModel):
    """A single recommended mitigation step."""

    action_id: str = Field(..., description="Unique action identifier (e.g., 'MIT-001')")
    title: str = Field(..., description="Short human-readable action title")
    description: str = Field(..., description="Detailed description of what to do")
    priority: int = Field(..., ge=1, le=5, description="Priority 1 (highest) to 5 (lowest)")
    automated: bool = Field(
        default=False,
        description="Whether this action can be executed automatically",
    )
    commands: list[str] = Field(
        default_factory=list,
        description="Shell commands or API calls to execute (if automated)",
    )


class TriageResult(BaseModel):
    """Structured output from the triage agent."""

    severity: Severity = Field(..., description="Overall severity classification")
    summary: str = Field(..., description="One-paragraph executive summary of the alert")
    indicators: list[ThreatIndicator] = Field(
        default_factory=list,
        description="Extracted IoCs from the raw telemetry",
    )
    affected_assets: list[str] = Field(
        default_factory=list,
        description="Hostnames, IPs, or service names impacted",
    )
    attack_vector: str = Field(default="", description="MITRE ATT&CK technique if identifiable")
    requires_escalation: bool = Field(
        default=False,
        description="True if the alert warrants immediate human attention",
    )


class MitigationPlan(BaseModel):
    """Structured output from the mitigation agent."""

    incident_id: str = Field(..., description="Unique incident identifier")
    actions: list[MitigationAction] = Field(..., description="Ordered list of mitigation actions")
    estimated_impact: str = Field(
        default="",
        description="Expected impact if mitigations are applied",
    )
    rollback_steps: list[str] = Field(
        default_factory=list,
        description="Steps to revert changes if mitigations cause issues",
    )


class IntelReport(BaseModel):
    """Structured output from the intel retrieval step (RAG + Graph)."""

    related_cves: list[dict[str, Any]] = Field(
        default_factory=list,
        description="CVE records matching the indicators",
    )
    threat_actors: list[str] = Field(
        default_factory=list,
        description="Known threat actors associated with the indicators",
    )
    historical_incidents: list[str] = Field(
        default_factory=list,
        description="Summaries of past incidents with similar IoCs",
    )
    graph_relationships: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Entity-relationship edges from the knowledge graph",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Composite risk score from 0.0 to 10.0",
    )


# ═══════════════════════════════════════════════════════════════
#  LangGraph Agent State
# ═══════════════════════════════════════════════════════════════


class AgentState(TypedDict):
    """Canonical state flowing through the LangGraph supervisor graph.

    The ``messages`` field uses LangGraph's ``add_messages`` reducer so
    that each node *appends* to the conversation history rather than
    overwriting it.
    """

    # ── Conversation ────────────────────────────────────────────
    messages: Annotated[list[AnyMessage], add_messages]

    # ── Routing & Control ──────────────────────────────────────
    current_agent: str
    next_agent: str
    iteration_count: int
    status: str  # PipelineStatus value

    # ── Triage Outputs ─────────────────────────────────────────
    severity: str  # Severity value
    triage_result: dict[str, Any] | None

    # ── Intel Outputs ──────────────────────────────────────────
    intel_report: dict[str, Any] | None

    # ── Mitigation Outputs ─────────────────────────────────────
    mitigation_plan: dict[str, Any] | None

    # ── Raw Input ──────────────────────────────────────────────
    raw_alert: str
    alert_source: str

    # ── Error Tracking ─────────────────────────────────────────
    errors: list[str]
