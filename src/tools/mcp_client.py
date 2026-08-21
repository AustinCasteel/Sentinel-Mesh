"""MCP client integration for connecting to the threat intel MCP server.

Spawns the MCP server as a subprocess (stdio transport) and exposes its
tools as LangChain-compatible ``BaseTool`` instances that can be bound to
LangGraph agents.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.tools import StructuredTool, ToolException
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from src.config import get_settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Low-level MCP client
# ═══════════════════════════════════════════════════════════════


class MCPClientManager:
    """Manages the lifecycle of an MCP client session over stdio.

    Usage::

        async with MCPClientManager() as manager:
            result = await manager.call_tool("lookup_cve", {"cve_id": "CVE-2024-3094"})
    """

    def __init__(self) -> None:
        import os

        settings = get_settings()
        env = dict(os.environ)
        if settings.abuseipdb_api_key:
            env["SENTINEL_ABUSEIPDB_API_KEY"] = settings.abuseipdb_api_key
        if settings.threatfox_auth_key:
            env["SENTINEL_THREATFOX_AUTH_KEY"] = settings.threatfox_auth_key

        self._server_params = StdioServerParameters(
            command=settings.mcp_server_command,
            args=settings.mcp_server_args.split(),
            env=env,
        )
        self._session: ClientSession | None = None
        self._context_stack: list[Any] = []

    async def __aenter__(self) -> MCPClientManager:
        """Start the MCP server subprocess and initialise the session."""
        transport_ctx = stdio_client(self._server_params)
        transport = await transport_ctx.__aenter__()
        self._context_stack.append(transport_ctx)

        read_stream, write_stream = transport
        session_ctx = ClientSession(read_stream, write_stream)
        self._session = await session_ctx.__aenter__()
        self._context_stack.append(session_ctx)

        await self._session.initialize()
        logger.info("MCP client connected to threat-intel server")
        return self

    async def __aexit__(self, *exc: Any) -> None:
        """Tear down the session and subprocess."""
        for ctx in reversed(self._context_stack):
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:
                logger.debug("Error closing MCP context", exc_info=True)
        self._context_stack.clear()
        self._session = None

    async def list_tools(self) -> list[dict[str, Any]]:
        """Return the list of tools advertised by the server."""
        if self._session is None:
            raise RuntimeError("MCP session not initialised")
        result = await self._session.list_tools()
        return [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
            }
            for tool in result.tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Invoke a tool on the MCP server and return the text result."""
        if self._session is None:
            raise RuntimeError("MCP session not initialised")
        result = await self._session.call_tool(name, arguments)
        # Concatenate all text content blocks
        parts: list[str] = []
        for content in result.content:
            if hasattr(content, "text"):
                parts.append(content.text)
            else:
                parts.append(str(content))
        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════
#  LangChain Tool Wrappers
# ═══════════════════════════════════════════════════════════════

# These are standalone functions that spawn a short-lived MCP session
# per call.  For production, use a persistent session pool.


async def _mcp_call(tool_name: str, **kwargs: Any) -> str:
    """Helper: open an MCP session, call a tool, return result."""
    try:
        async with MCPClientManager() as client:
            return await client.call_tool(tool_name, kwargs)
    except Exception as exc:
        raise ToolException(f"MCP call to {tool_name} failed: {exc}") from exc


async def _lookup_cve(cve_id: str) -> str:
    """Look up a CVE by its identifier via the MCP threat-intel server."""
    return await _mcp_call("lookup_cve", cve_id=cve_id)


async def _query_ip_reputation(ip_address: str) -> str:
    """Query IP reputation via the MCP threat-intel server."""
    return await _mcp_call("query_ip_reputation", ip_address=ip_address)


async def _parse_syslog(log_string: str) -> str:
    """Parse a raw syslog line via the MCP threat-intel server."""
    return await _mcp_call("parse_syslog", log_string=log_string)


def get_mcp_tools() -> list[StructuredTool]:
    """Return MCP-backed tools as LangChain StructuredTools.

    These tools can be passed directly to ``create_react_agent(tools=...)``
    in LangGraph.
    """
    return [
        StructuredTool.from_function(
            coroutine=_lookup_cve,
            name="lookup_cve",
            description=(
                "Look up a CVE vulnerability by its identifier (e.g. CVE-2024-3094). "
                "Returns CVSS score, affected products, MITRE ATT&CK mapping, and remediation."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_query_ip_reputation,
            name="query_ip_reputation",
            description=(
                "Query threat intelligence for an IP address. Returns risk score (0-100), "
                "categories, geolocation, associated malware, and threat actors."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_parse_syslog,
            name="parse_syslog",
            description=(
                "Parse a raw syslog line into structured fields. Extracts timestamp, "
                "hostname, process, PID, message, and any embedded IoCs (IPs, CVE IDs)."
            ),
        ),
    ]
