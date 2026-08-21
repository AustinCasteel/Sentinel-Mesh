"""LLM provider factory — unified interface for OpenAI, Ollama, Lemonade, and Bedrock.

The OpenAI-compatible interface is the primary path.  All local providers
(Ollama, Lemonade) expose OpenAI-compatible APIs, so ``ChatOpenAI`` is
reused across the board with different ``base_url`` values.

Providers:
  - **OpenAI**: Cloud API or any OpenAI-compatible endpoint.
  - **Ollama**: Local inference with easy model management (port 11434).
  - **Lemonade**: Lightweight local AI server with hybrid CPU/GPU/NPU
    execution and lower overhead than Ollama (port 13305).
  - **Bedrock**: AWS managed service via ``langchain-aws``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import lru_cache
from typing import cast

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from src.config import LLMProvider, Settings, get_settings

logger = logging.getLogger(__name__)


def _build_openai(settings: Settings) -> BaseChatModel:
    """Build a ChatOpenAI instance (works with any OpenAI-compatible API)."""
    return ChatOpenAI(
        model=settings.openai_model,
        api_key=settings.openai_api_key or "not-needed",
        base_url=settings.openai_api_base,
        temperature=0.1,
        max_retries=settings.max_retries,
    )


def _build_ollama(settings: Settings) -> BaseChatModel:
    """Build a ChatOpenAI pointing at a local Ollama endpoint.

    Ollama exposes an OpenAI-compatible API at ``/v1`` on port 11434.
    Good for easy model management and quick local iteration.
    """
    base = settings.ollama_base_url.rstrip("/")
    return ChatOpenAI(
        model=settings.ollama_model,
        api_key="ollama",
        base_url=f"{base}/v1",
        temperature=0.1,
        max_retries=settings.max_retries,
    )


def _build_lemonade(settings: Settings) -> BaseChatModel:
    """Build a ChatOpenAI pointing at a local Lemonade server.

    Lemonade (https://lemonade-server.ai) is a lightweight, open-source
    local AI server with several advantages over Ollama:

      - **Hybrid execution**: distributes inference across CPU, GPU, and
        NPU, making full use of heterogeneous hardware.
      - **Lower overhead**: leaner runtime with less resource consumption.
      - **Omni-modal**: supports chat, vision, image, speech, transcription,
        and embeddings from a single server.

    Lemonade exposes an OpenAI-compatible API on port 13305.
    """
    base = settings.lemonade_base_url.rstrip("/")
    return ChatOpenAI(
        model=settings.lemonade_model,
        api_key="lemonade",
        base_url=f"{base}/api/v1",
        temperature=0.1,
        max_retries=settings.max_retries,
    )


def _build_bedrock(settings: Settings) -> BaseChatModel:
    """Build a Bedrock-backed chat model via langchain-aws.

    Falls back to the OpenAI-compatible path if ``langchain-aws`` is not
    installed, logging a warning.
    """
    try:
        from langchain_aws import ChatBedrockConverse

        return cast(
            BaseChatModel,
            ChatBedrockConverse(
                model=settings.bedrock_model_id,
                region_name=settings.bedrock_region,
                temperature=0.1,
            ),
        )
    except ImportError:
        logger.warning(
            "langchain-aws not installed — falling back to OpenAI-compatible "
            "client for Bedrock.  Install with: uv add langchain-aws"
        )
        return _build_openai(settings)


_BUILDERS: dict[LLMProvider, Callable[[Settings], BaseChatModel]] = {
    LLMProvider.OPENAI: _build_openai,
    LLMProvider.OLLAMA: _build_ollama,
    LLMProvider.LEMONADE: _build_lemonade,
    LLMProvider.BEDROCK: _build_bedrock,
}


def get_llm(
    provider: LLMProvider | None = None,
    settings: Settings | None = None,
) -> BaseChatModel:
    """Return a ``BaseChatModel`` for the requested (or configured) provider.

    Parameters
    ----------
    provider:
        Override the configured provider.  If ``None``, uses
        ``settings.llm_provider``.
    settings:
        Inject settings (useful for testing).  If ``None``, uses the
        cached singleton.
    """
    settings = settings or get_settings()
    provider = provider or settings.llm_provider
    builder = _BUILDERS[provider]
    llm = builder(settings)
    model_name = getattr(llm, "model_name", getattr(llm, "model", str(provider.value)))
    logger.info("LLM initialised: provider=%s  model=%s", provider.value, model_name)
    return llm


@lru_cache(maxsize=1)
def get_default_llm() -> BaseChatModel:
    """Return a cached default LLM instance using the configured provider."""
    return get_llm()
