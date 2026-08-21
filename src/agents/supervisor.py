"""Supervisor Orchestrator — LangGraph multi-agent coordinator.

Uses ``langgraph-supervisor`` to create a supervisor workflow that:
  1. Routes incoming alerts to the Triage Agent
  2. Hands off enrichment to the Intel Retrieval Agent (planned)
  3. Sends triage + intel context to the Mitigation Agent
  4. Enforces iteration bounds and error handling

The supervisor is the "brain" of SentinelMesh — it decides which agent
to invoke next based on the current pipeline state.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph_supervisor import create_supervisor

from src.agents.mitigation_agent import create_mitigation_agent
from src.agents.triage_agent import create_triage_agent

logger = logging.getLogger(__name__)


SUPERVISOR_SYSTEM_PROMPT = """\
You are the SentinelMesh Supervisor — an autonomous security orchestrator \
managing a team of specialised incident response agents.

## Your Team
1. **triage** — SOC Tier-1 Analyst: parses raw alerts, extracts IoCs, \
   classifies severity. Send raw security telemetry here first.
2. **mitigation** — Senior IR Engineer: generates containment and \
   remediation plans based on triage and intel. Send here after triage.

## Orchestration Rules
1. **Always start with triage** for any new alert.
2. After triage, **route to mitigation** for remediation planning.
3. If triage indicates INFO or LOW severity with no IoCs, you may \
   skip mitigation and provide a brief "no action required" response.
4. Always provide a final executive summary after all agents complete.
5. If an agent produces an error, retry once then escalate to human review.

## Response Format
After all agents complete, provide:
- Overall severity assessment
- Key findings summary
- Mitigation actions (if any)
- Recommended next steps
"""


def build_supervisor_graph(llm: BaseChatModel) -> Any:
    """Build and compile the supervisor multi-agent graph.

    Parameters
    ----------
    llm:
        The chat model for the supervisor and all sub-agents.

    Returns
    -------
    A compiled LangGraph ``CompiledStateGraph`` ready for ``.invoke()``
    or ``.astream()``.
    """
    # ── Create specialised agents ──────────────────────────────
    triage_agent = create_triage_agent(llm)
    mitigation_agent = create_mitigation_agent(llm)

    # ── Create supervisor workflow ─────────────────────────────
    workflow = create_supervisor(
        [triage_agent, mitigation_agent],
        model=llm,
        prompt=SUPERVISOR_SYSTEM_PROMPT,
        include_agent_name="inline",
    )

    # ── Compile ────────────────────────────────────────────────
    graph = workflow.compile()
    logger.info("Supervisor graph compiled with agents: triage, mitigation")
    return graph


async def run_pipeline(
    alert: str,
    llm: BaseChatModel,
    *,
    source: str = "manual",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Run the full SentinelMesh pipeline on a raw alert.

    Parameters
    ----------
    alert:
        Raw alert text (syslog line, JSON payload, free-text description).
    llm:
        The chat model to use throughout the pipeline.
    source:
        Alert source identifier (e.g., 'siem', 'syslog', 'manual').
    session_id:
        Optional session ID for multi-turn context.

    Returns
    -------
    dict with the pipeline result including the full message history
    and any structured outputs from agents.
    """
    from src.core.telemetry import create_langfuse_trace, get_langfuse_callback, trace_span

    # ── Telemetry ──────────────────────────────────────────────
    _langfuse_trace = create_langfuse_trace(
        name="sentinel-mesh-pipeline",
        metadata={"source": source, "alert_preview": alert[:200]},
        session_id=session_id,
    )
    langfuse_cb = get_langfuse_callback()
    callbacks = [langfuse_cb] if langfuse_cb is not None else []

    with trace_span("pipeline_run", {"source": source}) as span:
        # ── Build graph ────────────────────────────────────────
        graph = build_supervisor_graph(llm)

        # ── Execute ────────────────────────────────────────────
        input_messages = {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Incoming security alert from {source}:\n\n"
                        f"{alert}\n\n"
                        "Please triage this alert and provide a mitigation plan "
                        "if warranted."
                    ),
                }
            ]
        }

        result = await graph.ainvoke(
            input_messages,
            config={"callbacks": callbacks, "recursion_limit": 10},
        )

        # ── Extract final response ─────────────────────────────
        messages = result.get("messages", [])
        final_response = ""
        for m in reversed(messages):
            content = getattr(m, "content", "")
            if isinstance(content, str) and content.strip():
                final_response = content
                break
            if isinstance(content, list):
                text_parts = [
                    p.get("text", "") for p in content if isinstance(p, dict) and p.get("text")
                ]
                if text_parts:
                    final_response = "\n".join(text_parts)
                    break
            # Fallback to reasoning_content if content was empty
            addl = getattr(m, "additional_kwargs", {}) or {}
            reasoning = addl.get("reasoning_content", "")
            if reasoning and isinstance(reasoning, str) and reasoning.strip():
                final_response = reasoning
                break

        if not final_response and messages:
            final_response = str(messages[-1])

        if span is not None:
            span.set_attribute("message_count", str(len(messages)))
            span.set_attribute("response_length", str(len(final_response)))

        pipeline_result = {
            "session_id": session_id,
            "source": source,
            "alert_preview": alert[:200],
            "final_response": final_response,
            "message_count": len(messages),
            "messages": [
                {
                    "role": getattr(m, "type", "unknown"),
                    "content": getattr(m, "content", str(m)),
                    "name": getattr(m, "name", None),
                    "tool_calls": getattr(m, "tool_calls", []),
                }
                for m in messages
            ],
        }

        if _langfuse_trace is not None and hasattr(_langfuse_trace, "end"):
            import contextlib

            with contextlib.suppress(Exception):
                _langfuse_trace.end(output=final_response)

        logger.info(
            "Pipeline complete: %d messages, response length %d",
            len(messages),
            len(final_response),
        )

        return pipeline_result
