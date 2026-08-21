"""SentinelMesh configuration via Pydantic BaseSettings.

All settings are loaded from environment variables with the ``SENTINEL_`` prefix,
or from a ``.env`` file at the project root.  See ``.env.example`` for the full
template.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class LLMProvider(StrEnum):
    """Supported LLM provider backends.

    - ``openai``:    OpenAI API (or any OpenAI-compatible endpoint via base_url).
    - ``ollama``:    Ollama local inference server — easy model management.
    - ``lemonade``:  Lemonade local AI server — lightweight, hybrid CPU/GPU/NPU.
    - ``bedrock``:   AWS Bedrock managed service.
    """

    OPENAI = "openai"
    OLLAMA = "ollama"
    LEMONADE = "lemonade"
    BEDROCK = "bedrock"


class Settings(BaseSettings):
    """Central configuration for the SentinelMesh system.

    Values are resolved in order:
      1. Explicit env vars (``SENTINEL_*``)
      2. ``.env`` file
      3. Defaults below
    """

    # ── LLM Provider ────────────────────────────────────────────
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OPENAI,
        description="Active LLM backend: openai, ollama, lemonade, or bedrock.",
    )

    # ── OpenAI / OpenAI-Compatible ──────────────────────────────
    openai_api_key: str = Field(default="", description="OpenAI API key")
    openai_api_base: str = Field(
        default="https://api.openai.com/v1",
        description="Base URL — override for any OpenAI-compatible endpoint.",
    )
    openai_model: str = Field(default="gpt-4o", description="Model name for OpenAI provider")

    # ── Ollama (local) ─────────────────────────────────────────
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL",
    )
    ollama_model: str = Field(default="llama3.1", description="Model tag for Ollama")

    # ── Lemonade (local, hybrid CPU/GPU/NPU) ───────────────────
    lemonade_base_url: str = Field(
        default="http://localhost:13305",
        description="Lemonade server URL (https://lemonade-server.ai)",
    )
    lemonade_model: str = Field(
        default="llama-3.1-8b",
        description="Model name for Lemonade. Lemonade supports hybrid "
        "execution across CPU, GPU, and NPU for lower overhead.",
    )

    # ── AWS Bedrock ──────────────────────────────────
    bedrock_region: str = Field(default="us-east-1", description="AWS region for Bedrock")
    bedrock_model_id: str = Field(
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        description="Bedrock model identifier",
    )

    # ── Neo4j Knowledge Graph ──────────────────────────────────
    neo4j_uri: str = Field(default="bolt://localhost:7687", description="Neo4j Bolt URI")
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(default="sentinel-mesh", description="Neo4j password")

    # ── Qdrant Vector Store ────────────────────────────────────
    qdrant_host: str = Field(default="localhost", description="Qdrant host")
    qdrant_port: int = Field(default=6333, description="Qdrant REST port")
    qdrant_collection: str = Field(
        default="threat_intel",
        description="Qdrant collection name for threat intelligence embeddings",
    )

    # ── Langfuse ───────────────────────────────────────────────
    langfuse_public_key: str = Field(default="", description="Langfuse public key")
    langfuse_secret_key: str = Field(default="", description="Langfuse secret key")
    langfuse_host: str = Field(
        default="http://localhost:3000",
        description="Langfuse server URL (Docker or cloud)",
    )

    # ── OpenTelemetry ──────────────────────────────────────────
    otel_exporter_endpoint: str = Field(
        default="http://localhost:4317",
        description="OTLP gRPC exporter endpoint",
    )
    otel_service_name: str = Field(default="sentinel-mesh", description="OTel service name")

    # ── Threat Intel APIs ──────────────────────────────────────
    abuseipdb_api_key: str = Field(
        default="",
        description="AbuseIPDB API key for IP reputation scoring",
    )
    threatfox_auth_key: str = Field(
        default="",
        description="ThreatFox API auth key for C2/malware indicators",
    )

    # ── MCP Server ─────────────────────────────────────────────
    mcp_server_command: str = Field(
        default="python",
        description="Command to launch the MCP threat intel server",
    )
    mcp_server_args: str = Field(
        default="mcp_servers/threat_intel_server.py",
        description="Arguments for the MCP server command",
    )

    # ── Agent Tuning ───────────────────────────────────────────
    max_retries: int = Field(default=3, ge=1, description="Max retries per agent step")
    max_iterations: int = Field(
        default=10,
        ge=1,
        description="Max supervisor loop iterations before forced termination",
    )

    model_config = {
        "env_prefix": "SENTINEL_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


Settings.model_rebuild()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton of the application settings."""
    return Settings()
