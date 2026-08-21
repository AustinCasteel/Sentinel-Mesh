# SentinelMesh

**Autonomous Threat Triage & Incident Response Multi-Agent System**

A mission-relevant rapid prototype demonstrating multi-agent orchestration for security operations. SentinelMesh ingests raw security telemetry, queries external threat intelligence via **Model Context Protocol (MCP)**, correlates indicators with **hybrid RAG (Qdrant + Neo4j GraphRAG)**, and produces actionable mitigation plans — all with full **OpenTelemetry + Langfuse tracing** and an **automated evaluation harness**.

---

## Architecture

```mermaid
graph TB
    subgraph Client
        API[FastAPI REST/SSE<br/>POST /v1/triage]
    end

    subgraph Orchestration
        SUP[Supervisor Agent<br/>LangGraph]
        SUP --> TRI[Triage Agent<br/>SOC Tier-1 Analyst]
        SUP --> MIT[Mitigation Agent<br/>IR Engineer]
    end

    subgraph Tools
        MCP[MCP Server<br/>Threat Intel Tools]
        LOCAL[Local Tools<br/>Deterministic Utils]
    end

    subgraph Memory
        QDRANT[(Qdrant<br/>Vector Store)]
        NEO4J[(Neo4j<br/>Knowledge Graph)]
    end

    subgraph Observability
        OTEL[OpenTelemetry<br/>→ Jaeger]
        LF[Langfuse<br/>LLM Traces]
    end

    API --> SUP
    TRI --> MCP
    TRI --> LOCAL
    MIT --> LOCAL
    TRI -.-> QDRANT
    TRI -.-> NEO4J
    SUP -.-> OTEL
    SUP -.-> LF
```

## Quick Start

### Prerequisites

- Python 3.11+
- [UV](https://docs.astral.sh/uv/) (package manager)
- Docker & Docker Compose (for infrastructure services)

### 1. Clone & Install

```bash
git clone https://github.com/austincasteel/sentinel-mesh.git
cd sentinel-mesh
cp .env.example .env  # Edit with your API keys
uv sync
```

### 2. Start Infrastructure

```bash
docker compose up -d
```

### 3. Run the API

```bash
uv run uvicorn src.app:app --reload
```

### 4. Interactive Terminal Dashboard (TUI)

Launch the live SOC Command Center in your terminal to inspect incoming alerts, browse triage resolutions, and simulate synthetic attacks with one keystroke:

```bash
uv run sentinel-tui
# or
uv run python src/tui.py
```

- Press **`s`** to open the scenario injector and simulate security events live (SSH brute force, XZ backdoor CVE-2024-3094, Log4Shell, FortiOS VPN exploit).
- Press **`↑` / `↓`** to navigate between ingested alerts.
- Switch tabs to inspect the **Executive Summary**, **Extracted IoCs**, or generated **Mitigation Firewall Rules**.
- Press **`r`** to refresh feed, **`q`** to quit.

### 5. Submit an Alert via cURL / REST API

```bash
curl -X POST http://localhost:8000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{
    "alert": "Mar 15 14:23:01 webserver sshd[12345]: Failed password for root from 185.220.101.1 port 22 ssh2",
    "source": "syslog"
  }'
```

### One-Command Docker Setup

```bash
docker compose up --build
```

This starts everything: the SentinelMesh API, Qdrant, Neo4j, Jaeger, and Langfuse.

---

## LLM Provider Configuration

SentinelMesh supports four LLM backends through a unified factory pattern:

| Provider | Config | Use Case |
|----------|--------|----------|
| **OpenAI** (default) | `SENTINEL_LLM_PROVIDER=openai` | Primary development. Compatible with any OpenAI-API endpoint. |
| **Ollama** | `SENTINEL_LLM_PROVIDER=ollama` | Local/offline development. Easy model management. |
| **Lemonade** | `SENTINEL_LLM_PROVIDER=lemonade` | Local/offline with hybrid CPU/GPU/NPU execution and lower overhead. |
| **AWS Bedrock** | `SENTINEL_LLM_PROVIDER=bedrock` | AWS-native deployments. |

The OpenAI provider works with **any OpenAI-compatible API** — point `SENTINEL_OPENAI_API_BASE` at vLLM or any other compatible endpoint.

### Ollama vs Lemonade

Both are local inference servers, but they serve different niches:

| | Ollama | Lemonade |
|---|--------|----------|
| **Best for** | Quick setup, broad model library | Performance-sensitive workloads |
| **Overhead** | Standard | Lower resource consumption |
| **Hardware** | CPU or GPU | Hybrid CPU/GPU/NPU — splits inference across all available silicon |
| **Default port** | 11434 | 13305 |
| **Install** | See [ollama.com](https://ollama.com) | See [lemonade-server.ai](https://lemonade-server.ai) |
| **Multi-modal** | Text, vision | Text, vision, image, speech, transcription, embeddings |

---

## MCP Tools

The threat intelligence MCP server exposes three tools backed by live APIs:

| Tool | Source | Description |
|------|--------|-------------|
| `lookup_cve` | [CIRCL](https://cve.circl.lu) | CVE lookup via the CIRCL Vulnerability Lookup API — aggregates global sources (NVD, Red Hat, vendor advisories) |
| `query_ip_reputation` | [AbuseIPDB](https://www.abuseipdb.com) + [ThreatFox](https://threatfox.abuse.ch) | IP reputation scoring via AbuseIPDB, C2/malware/threat actor enrichment via abuse.ch ThreatFox |
| `parse_syslog` | Local | Parse RFC 3164 syslog lines with IoC extraction (no external API) |

All external API calls degrade gracefully — tools return whatever data is available plus a `"warnings"` list when API keys are not configured.

Run standalone: `uv run python mcp_servers/threat_intel_server.py`

---

## Evaluation

Run the automated evaluation harness against 10 synthetic test scenarios:

```bash
uv run python eval/run_evals.py
uv run python eval/run_evals.py --case EVAL-001    # Single case
uv run python eval/run_evals.py --provider ollama   # Override provider
uv run python eval/run_evals.py --output results.json
```

Scoring dimensions:
- **Tool Selection Precision** — Did agents pick the right tools?
- **Severity Accuracy** — Classification matches expected severity?
- **IoC Extraction Recall** — All expected indicators found?
- **Mitigation Completeness** — Key remediation actions present?

---

## Design Decisions & Trade-offs

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Orchestration** | LangGraph + langgraph-supervisor | Battle-tested framework with built-in checkpointing. `create_supervisor` provides clean multi-agent routing. |
| **Knowledge Graph** | Neo4j (Docker) | Real graph database with Cypher queries. |
| **Vector Store** | Qdrant | Production-grade with excellent filtering. |
| **LLM Strategy** | 4-provider factory | OpenAI for cloud, Ollama for easy local dev, Lemonade for hybrid CPU/GPU/NPU with lower overhead, Bedrock for AWS. |
| **MCP vs Function Calling** | MCP Protocol | Standardized tool boundary. Decouples tool implementation from agent logic. Industry-standard protocol. |
| **Observability** | OTel + Langfuse | OTel for infrastructure traces (vendor-neutral). Langfuse for LLM-specific observability (token usage, cost, prompt tracking). |
| **Terminal UI** | Textual | Rich reactive terminal dashboard with live streaming, alert navigation, and scenario simulation. |
| **Package Manager** | UV | 10-100x faster than pip/poetry. Modern, growing ecosystem. |

### Enterprise Local SOC: Architecture & Infrastructure Profile

SentinelMesh is intentionally architected to mirror an **enterprise-grade, sovereign SOC environment running locally**:

1. **Zero Data Leakage (Sovereign & Air-Gapped Ready)**:
   - Security logs, internal asset topologies, and remediation scripts frequently contain confidential infrastructure details.
   - SentinelMesh can run entirely on local inference (Lemonade / Ollama) with self-hosted knowledge graphs (Neo4j), vector search (Qdrant), and on-premise observability (Jaeger + Langfuse v4).
2. **Infrastructure Footprint & Graceful Fallback**:
   - **Full Enterprise Profile**: Starts the complete SOC observability stack (ClickHouse, MinIO, Redis queue, Postgres, Langfuse Worker & Web, Neo4j, Qdrant, and Jaeger) via `docker compose up -d`.
   - **Lightweight Profile**: If running on resource-constrained hardware, you can start only `jaeger` and `qdrant` (or run purely in-memory). Telemetry and tools degrade gracefully with zero crashes if any backend service is stopped.

---

## Project Structure

```
sentinel-mesh/
├── .github/workflows/ci.yml       # Ruff, Mypy, Pytest CI pipeline
├── docker-compose.yml              # Full infrastructure stack
├── Dockerfile                      # Production container
├── pyproject.toml                  # UV/Hatchling project config
├── eval/
│   ├── benchmarks/gold_standard.json  # 10 synthetic test scenarios
│   └── run_evals.py                # Evaluation harness
├── mcp_servers/
│   └── threat_intel_server.py      # MCP threat intelligence server
├── src/
│   ├── app.py                      # FastAPI REST/SSE endpoints
│   ├── tui.py                      # Interactive Terminal UI dashboard (Textual)
│   ├── config.py                   # Pydantic BaseSettings
│   ├── agents/
│   │   ├── state.py                # TypedDict state + Pydantic schemas
│   │   ├── supervisor.py           # LangGraph supervisor orchestrator
│   │   ├── triage_agent.py         # SOC Tier-1 triage
│   │   └── mitigation_agent.py     # IR Engineer mitigation
│   ├── core/
│   │   ├── llm_factory.py          # Provider factory (OpenAI/Ollama/Bedrock)
│   │   └── telemetry.py            # OTel + Langfuse dual tracing
│   ├── memory/
│   │   ├── hybrid_retriever.py     # Qdrant + Neo4j hybrid RAG
│   │   └── session_store.py        # Multi-turn session memory
│   └── tools/
│       ├── mcp_client.py           # MCP client → LangChain tool bridge
│       └── local_tools.py          # Deterministic Python utilities
└── tests/
```

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 ([GPL-3.0](LICENSE)). See the [LICENSE](LICENSE) file for details.
