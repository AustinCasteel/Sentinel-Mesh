"""Triage Agent — parses raw security telemetry and classifies severity.

This agent is the first step in the SentinelMesh pipeline.  It receives
raw alert data (syslog, JSON, free-text) and produces a structured
``TriageResult`` with severity classification, extracted IoCs, affected
assets, and an escalation recommendation.

Implemented as a LangGraph ``create_react_agent`` with access to both
MCP tools (for external enrichment) and local tools (for deterministic
classification).
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.prebuilt import create_react_agent

from src.tools.local_tools import classify_severity, extract_iocs, query_knowledge_graph
from src.tools.mcp_client import get_mcp_tools

logger = logging.getLogger(__name__)


TRIAGE_SYSTEM_PROMPT = """\
You are a Security Operations Center (SOC) Tier-1 Triage Analyst within \
the SentinelMesh autonomous incident response system.

## Your Mission
Analyse the incoming security alert or raw telemetry and produce a \
structured triage assessment.

## Process
1. **Parse** the raw data — use `parse_syslog` for syslog-format logs.
2. **Extract IoCs** — use `extract_iocs` to pull out IPs, CVEs, hashes, \
   domains, and emails.
3. **Enrich** — use `lookup_cve` for any CVE IDs, `query_ip_reputation` \
   for suspicious IP addresses, and `query_knowledge_graph` to inspect internal \
   assets and threat actor relationships.
4. **Classify Severity** — use `classify_severity` with the CVSS score and \
   context to assign severity.
5. **Synthesise** — produce a clear, concise triage summary.

## Output Requirements
Your final response MUST include:
- **Severity**: critical / high / medium / low / info
- **Summary**: 2-3 sentence executive summary
- **Indicators**: list of IoCs with type, value, and confidence
- **Affected Assets**: hostnames or IPs impacted
- **Attack Vector**: MITRE ATT&CK technique if identifiable
- **Escalation**: whether this requires immediate human attention

Be precise and evidence-based.  Never speculate without marking it as such.
"""


def create_triage_agent(llm: BaseChatModel) -> Any:
    """Build and return the triage react agent.

    Parameters
    ----------
    llm:
        The chat model to use for reasoning.

    Returns
    -------
    A compiled LangGraph react agent.
    """
    # Combine MCP tools + local deterministic tools
    tools = [*get_mcp_tools(), classify_severity, extract_iocs, query_knowledge_graph]

    agent = create_react_agent(
        model=llm,
        tools=tools,
        name="triage",
        prompt=TRIAGE_SYSTEM_PROMPT,
    )

    logger.info("Triage agent created with %d tools", len(tools))
    return agent
