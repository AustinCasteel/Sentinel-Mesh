"""FastAPI application — REST and SSE endpoints for SentinelMesh.

Exposes:
  - ``POST /v1/triage``         — Submit an alert for full pipeline processing
  - ``POST /v1/triage/stream``  — Same, but with Server-Sent Events streaming
  - ``GET  /health``            — Health check
  - ``GET  /v1/sessions``       — List active sessions
"""

from __future__ import annotations

import json
import logging
import uuid
import warnings
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from src.agents.supervisor import build_supervisor_graph, run_pipeline
from src.config import get_settings
from src.core.llm_factory import get_llm
from src.core.telemetry import flush_telemetry, init_telemetry
from src.memory.session_store import SessionStore, alert_store
from src.tools.local_tools import extract_iocs

# Filter benign FastMCP forward-reference warning
warnings.filterwarnings("ignore", message=".*Field 'lifespan' has an incomplete definition.*")


class EndpointFilter(logging.Filter):
    """Filter out routine dashboard polling endpoints from console logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return "/v1/alerts" not in msg


logging.getLogger("uvicorn.access").addFilter(EndpointFilter())

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
#  Lifespan
# ═══════════════════════════════════════════════════════════════

session_store = SessionStore()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown hooks."""
    # ── Startup ────────────────────────────────────────────────
    init_telemetry()
    settings = get_settings()

    # Seed Neo4j knowledge graph and Qdrant vector store
    try:
        from src.memory.hybrid_retriever import KnowledgeGraph, VectorStore

        kg = KnowledgeGraph()
        kg.seed_sample_graph()
        kg.close()

        vs = VectorStore()
        vs.ensure_collection(vector_size=4)
        logger.info("Initialized Neo4j knowledge graph and Qdrant collections")
    except Exception:
        logger.warning("Database seeding during startup encountered an issue", exc_info=True)

    logger.info(
        "SentinelMesh starting — provider=%s  model=%s",
        settings.llm_provider.value,
        settings.openai_model
        if settings.llm_provider.value == "openai"
        else settings.lemonade_model
        if settings.llm_provider.value == "lemonade"
        else settings.ollama_model,
    )
    yield
    # ── Shutdown ───────────────────────────────────────────────
    flush_telemetry()
    logger.info("SentinelMesh shutdown complete")


# ═══════════════════════════════════════════════════════════════
#  App
# ═══════════════════════════════════════════════════════════════

app = FastAPI(
    title="SentinelMesh",
    description=(
        "Autonomous Threat Triage & Incident Response Multi-Agent System. "
        "Submit security alerts for AI-driven analysis, enrichment, and "
        "mitigation planning."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════
#  Request / Response Schemas
# ═══════════════════════════════════════════════════════════════


class TriageRequest(BaseModel):
    """Payload for submitting a security alert."""

    alert: str = Field(
        ...,
        min_length=1,
        description="Raw alert text — syslog line, JSON payload, or free-text description.",
        examples=[
            "Mar 15 14:23:01 webserver sshd[12345]: Failed password for root from 185.220.101.1 port 22 ssh2"
        ],
    )
    source: str = Field(
        default="manual",
        description="Alert source identifier (e.g., 'siem', 'syslog', 'manual').",
    )
    session_id: str | None = Field(
        default=None,
        description="Session ID for multi-turn context. Auto-generated if omitted.",
    )


class TriageResponse(BaseModel):
    """Response from the triage pipeline."""

    session_id: str
    source: str
    alert_preview: str
    final_response: str
    message_count: int


# ═══════════════════════════════════════════════════════════════
#  Endpoints
# ═══════════════════════════════════════════════════════════════


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": "sentinel-mesh",
        "llm_provider": settings.llm_provider.value,
    }


@app.post("/v1/triage", response_model=TriageResponse, tags=["Pipeline"])
async def triage_alert(request: TriageRequest) -> TriageResponse:
    """Submit a security alert for full pipeline processing.

    The alert passes through: Triage → Intel Enrichment → Mitigation.
    Returns the complete analysis and mitigation plan.
    """
    import re
    import time

    session_id = request.session_id or str(uuid.uuid4())
    alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

    # Record alert into alert_store
    alert_store.record_alert(
        alert_id=alert_id,
        session_id=session_id,
        source=request.source,
        raw_alert=request.alert,
    )

    start_time = time.monotonic()
    try:
        llm = get_llm()
        result = await run_pipeline(
            alert=request.alert,
            llm=llm,
            source=request.source,
            session_id=session_id,
        )
        flush_telemetry()
        duration = time.monotonic() - start_time

        # Extract severity and indicators for dashboard record
        final_resp = result.get("final_response", "")
        severity = "UNKNOWN"
        sev_match = re.search(r"(?i)\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", final_resp)
        if sev_match:
            severity = sev_match.group(1).upper()

        # Extract IoCs using local regex extractor
        iocs: list[str] = []
        try:
            raw_extracted = extract_iocs.invoke({"text": f"{request.alert} {final_resp}"})
            extracted_dict = (
                json.loads(raw_extracted) if isinstance(raw_extracted, str) else raw_extracted
            )
            ioc_groups = extracted_dict.get("iocs", {}) if isinstance(extracted_dict, dict) else {}
            for items in ioc_groups.values():
                if isinstance(items, list):
                    iocs.extend(items)
        except Exception:
            pass

        alert_store.update_alert(
            alert_id_or_session=session_id,
            severity=severity,
            status="COMPLETED",
            final_response=final_resp,
            iocs=sorted(list(set(iocs))),
            message_count=result.get("message_count", 0),
            duration_seconds=duration,
        )

        return TriageResponse(
            session_id=session_id,
            source=result["source"],
            alert_preview=result["alert_preview"],
            final_response=result["final_response"],
            message_count=result["message_count"],
        )
    except Exception as exc:
        logger.exception("Pipeline execution failed")
        alert_store.update_alert(
            alert_id_or_session=session_id,
            status="FAILED",
            error=str(exc),
            duration_seconds=time.monotonic() - start_time,
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/triage/stream", tags=["Pipeline"])
async def triage_alert_stream(request: TriageRequest) -> EventSourceResponse:
    """Submit a security alert with Server-Sent Events streaming.

    Events are emitted as each agent completes its work, providing
    real-time visibility into the pipeline progress.
    """
    session_id = request.session_id or str(uuid.uuid4())
    alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

    alert_store.record_alert(
        alert_id=alert_id,
        session_id=session_id,
        source=request.source,
        raw_alert=request.alert,
    )

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
            llm = get_llm()
            graph = build_supervisor_graph(llm)

            input_messages = {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            f"Incoming security alert from {request.source}:\n\n"
                            f"{request.alert}\n\n"
                            "Please triage this alert and provide a mitigation "
                            "plan if warranted."
                        ),
                    }
                ]
            }

            # Stream events from the graph
            async for event in graph.astream_events(input_messages, version="v2"):
                kind = event.get("event", "")
                name = event.get("name", "")

                if kind == "on_chat_model_start":
                    yield {
                        "event": "agent_start",
                        "data": json.dumps({"agent": name, "session_id": session_id}),
                    }
                elif kind == "on_chat_model_stream":
                    chunk = event.get("data", {}).get("chunk", "")
                    content = ""
                    if hasattr(chunk, "content"):
                        content = chunk.content
                    if content:
                        yield {
                            "event": "token",
                            "data": json.dumps({"content": content, "agent": name}),
                        }
                elif kind == "on_tool_end":
                    output = event.get("data", {}).get("output", "")
                    yield {
                        "event": "tool_result",
                        "data": json.dumps(
                            {
                                "tool": name,
                                "output_preview": str(output)[:500],
                            }
                        ),
                    }
                elif kind == "on_chain_end" and name == "LangGraph":
                    alert_store.update_alert(session_id, status="COMPLETED")
                    yield {
                        "event": "pipeline_complete",
                        "data": json.dumps({"session_id": session_id}),
                    }

        except Exception as exc:
            logger.exception("Streaming pipeline failed")
            alert_store.update_alert(session_id, status="FAILED", error=str(exc))
            yield {
                "event": "error",
                "data": json.dumps({"error": str(exc)}),
            }

    return EventSourceResponse(event_generator())


@app.get("/v1/alerts", tags=["Alerts"])
async def list_alerts(limit: int = 20) -> list[dict[str, Any]]:
    """List recent alert records with triage status and responses."""
    return alert_store.list_alerts(limit=limit)


@app.get("/v1/alerts/{alert_id_or_session}", tags=["Alerts"])
async def get_alert(alert_id_or_session: str) -> dict[str, Any]:
    """Get full details of an alert by alert ID or session ID."""
    record = alert_store.get_alert(alert_id_or_session)
    if not record:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return record.to_dict()


@app.get("/v1/sessions", tags=["Sessions"])
async def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    return session_store.list_sessions()


# ═══════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
