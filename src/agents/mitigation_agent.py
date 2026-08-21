"""Mitigation Agent — generates structured remediation plans.

This agent takes the triage results and intel enrichment, then produces
a prioritised, actionable ``MitigationPlan`` with specific steps,
commands, and rollback procedures.

Implemented as a LangGraph ``create_react_agent`` with access to local
tools for deterministic operations (firewall rules, CIDR validation).
"""

from __future__ import annotations

import logging

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.prebuilt import create_react_agent

from src.tools.local_tools import (
    generate_firewall_rule,
    validate_network_cidr,
)

logger = logging.getLogger(__name__)


MITIGATION_SYSTEM_PROMPT = """\
You are a Senior Incident Response Engineer within the SentinelMesh \
autonomous incident response system.

## Your Mission
Given the triage assessment and threat intelligence, generate a \
comprehensive, prioritised mitigation plan.

## Process
1. **Review** the triage summary, IoCs, and intel enrichment from \
   previous agents.
2. **Assess** the attack surface — use `validate_network_cidr` to \
   verify network ranges if needed.
3. **Generate containment actions** — use `generate_firewall_rule` to \
   create network-level blocks for malicious IPs.
4. **Prioritise** actions by impact and urgency.
5. **Include rollback steps** for every automated action.

## Output Requirements
Your final response MUST include a structured mitigation plan:
- **Incident ID**: generated from the alert context
- **Actions**: ordered list, each with:
  - action_id (e.g., MIT-001)
  - title
  - description
  - priority (1=highest to 5=lowest)
  - automated (true/false)
  - commands (if automated)
- **Estimated Impact**: expected effect of applying all mitigations
- **Rollback Steps**: how to revert each automated action

## Principles
- **Containment first**: block active threats before investigating.
- **Least disruption**: prefer targeted blocks over broad network changes.
- **Auditability**: every action must be traceable and reversible.
- **Evidence preservation**: never destroy forensic data.
"""


def create_mitigation_agent(llm: BaseChatModel) -> any:
    """Build and return the mitigation react agent.

    Parameters
    ----------
    llm:
        The chat model to use for reasoning.

    Returns
    -------
    A compiled LangGraph react agent.
    """
    tools = [generate_firewall_rule, validate_network_cidr]

    agent = create_react_agent(
        model=llm,
        tools=tools,
        name="mitigation",
        prompt=MITIGATION_SYSTEM_PROMPT,
    )

    logger.info("Mitigation agent created with %d tools", len(tools))
    return agent
