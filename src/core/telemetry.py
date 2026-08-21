"""OpenTelemetry + Langfuse dual observability layer.

Initialises both backends at import time (when ``init_telemetry`` is called)
and exposes helpers for tracing agent steps, tool calls, and LLM invocations.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from src.config import get_settings

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
#  Global state — lazily initialised
# ═══════════════════════════════════════════════════════════════

_otel_tracer: Any | None = None
_langfuse_client: Any | None = None


# ───────────────────────────────────────────────────────────────
#  OpenTelemetry
# ───────────────────────────────────────────────────────────────


def _init_otel() -> Any:
    """Set up the OpenTelemetry SDK with OTLP gRPC exporter."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        settings = get_settings()
        resource = Resource.create({"service.name": settings.otel_service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer("sentinel-mesh")
        logger.info("OpenTelemetry initialised → %s", settings.otel_exporter_endpoint)
        return tracer
    except Exception:
        logger.warning("OpenTelemetry init failed — tracing disabled", exc_info=True)
        return None


# ───────────────────────────────────────────────────────────────
#  Langfuse
# ───────────────────────────────────────────────────────────────


def _init_langfuse() -> Any:
    """Set up the Langfuse Python SDK client."""
    try:
        import os

        from langfuse import Langfuse

        settings = get_settings()
        pub_key = settings.langfuse_public_key or ""
        sec_key = settings.langfuse_secret_key or ""

        # Ignore unconfigured or template placeholder keys
        if (
            not pub_key
            or not sec_key
            or pub_key.startswith("pk-...")
            or sec_key.startswith("sk-...")
        ):
            logger.info("Langfuse keys not configured — LLM tracing disabled")
            return None

        os.environ["LANGFUSE_PUBLIC_KEY"] = pub_key
        os.environ["LANGFUSE_SECRET_KEY"] = sec_key
        os.environ["LANGFUSE_HOST"] = settings.langfuse_host

        client = Langfuse(
            public_key=pub_key,
            secret_key=sec_key,
            host=settings.langfuse_host,
        )
        logger.info("Langfuse initialised → %s", settings.langfuse_host)
        return client
    except Exception:
        logger.warning("Langfuse init failed — LLM tracing disabled", exc_info=True)
        return None


# ═══════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════


def init_telemetry() -> None:
    """Eagerly initialise both telemetry backends.

    Safe to call multiple times — subsequent calls are no-ops.
    """
    global _otel_tracer, _langfuse_client
    if _otel_tracer is None:
        _otel_tracer = _init_otel()
    if _langfuse_client is None:
        _langfuse_client = _init_langfuse()


def get_langfuse_callback() -> Any | None:
    """Return a LangChain CallbackHandler for tracing with Langfuse."""
    if _langfuse_client is None:
        return None
    try:
        from langfuse.langchain import CallbackHandler

        return CallbackHandler()
    except Exception:
        logger.debug("Failed to create Langfuse CallbackHandler", exc_info=True)
        return None


@contextmanager
def trace_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Context manager that creates an OTel span.

    Falls back to a no-op if OpenTelemetry is not initialised.

    Usage::

        with trace_span("triage_agent", {"alert_id": "A-123"}) as span:
            result = do_work()
            span.set_attribute("severity", result.severity)
    """
    if _otel_tracer is not None:
        with _otel_tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, str(v))
            yield span
    else:
        yield None


def create_langfuse_trace(
    name: str,
    *,
    metadata: dict[str, Any] | None = None,
    session_id: str | None = None,
) -> Any | None:
    """Create a new Langfuse trace for an end-to-end pipeline run.

    Supports both Langfuse SDK v4+ (start_observation) and legacy v2/v3 (trace).
    Returns the trace/observation object, or ``None`` if Langfuse is not available.
    """
    if _langfuse_client is None:
        return None
    try:
        if hasattr(_langfuse_client, "start_observation"):
            return _langfuse_client.start_observation(
                name=name,
                as_type="chain",
                metadata=metadata or {},
            )
        if hasattr(_langfuse_client, "trace"):
            return _langfuse_client.trace(
                name=name,
                metadata=metadata or {},
                session_id=session_id,
            )
    except Exception:
        logger.debug("Failed to create Langfuse trace", exc_info=True)
    return None


def langfuse_generation(
    trace: Any,
    *,
    name: str,
    model: str,
    input_data: Any,
    output_data: Any,
    usage: dict[str, int] | None = None,
) -> None:
    """Log a single LLM generation to a Langfuse trace."""
    if trace is None:
        return
    try:
        if hasattr(trace, "generation"):
            trace.generation(
                name=name,
                model=model,
                input=input_data,
                output=output_data,
                usage=usage or {},
            )
    except Exception:
        logger.debug("Failed to record Langfuse generation", exc_info=True)


def flush_telemetry() -> None:
    """Flush any buffered telemetry data.  Call on shutdown."""
    if _langfuse_client is not None:
        try:
            _langfuse_client.flush()
        except Exception:
            logger.debug("Langfuse flush failed", exc_info=True)
