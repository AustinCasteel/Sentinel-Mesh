"""Session memory store — multi-turn conversation window with periodic summarisation.

Manages conversation history for the supervisor agent loop with:
  - A sliding window of recent messages
  - Periodic LLM-driven summarisation of older messages
  - Session persistence (in-memory for now, easily swappable to Redis/DB)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

logger = logging.getLogger(__name__)


class SessionStore:
    """In-memory session store with sliding window and summarisation.

    Parameters
    ----------
    window_size:
        Maximum number of messages to keep in the active window.
    summary_threshold:
        When the window exceeds this many messages, trigger summarisation
        of the oldest messages.
    """

    def __init__(
        self,
        window_size: int = 20,
        summary_threshold: int = 15,
    ) -> None:
        self._window_size = window_size
        self._summary_threshold = summary_threshold
        self._sessions: dict[str, SessionData] = {}

    def get_or_create(self, session_id: str) -> SessionData:
        """Return the session data for the given ID, creating if needed."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionData(session_id=session_id)
            logger.info("Created new session: %s", session_id)
        return self._sessions[session_id]

    def add_message(self, session_id: str, message: BaseMessage) -> None:
        """Append a message to the session window."""
        session = self.get_or_create(session_id)
        session.messages.append(message)
        session.updated_at = datetime.now()

    def get_messages(self, session_id: str) -> list[BaseMessage]:
        """Return the active window of messages, prepended with any summary."""
        session = self.get_or_create(session_id)
        messages: list[BaseMessage] = []

        # Prepend rolling summary if available
        if session.summary:
            messages.append(SystemMessage(content=f"[Session Summary]\n{session.summary}"))

        # Return the most recent messages within the window
        messages.extend(session.messages[-self._window_size :])
        return messages

    def needs_summarisation(self, session_id: str) -> bool:
        """Check if the session has enough messages to trigger summarisation."""
        session = self.get_or_create(session_id)
        return len(session.messages) > self._summary_threshold

    async def summarise(self, session_id: str, llm: Any) -> str:
        """Summarise older messages and compact the session.

        Moves messages beyond the window into a rolling summary using the
        provided LLM, then truncates the message list to ``window_size / 2``.

        Parameters
        ----------
        llm:
            A LangChain ``BaseChatModel`` instance for generating the summary.

        Returns
        -------
        The generated summary text.
        """
        session = self.get_or_create(session_id)

        if len(session.messages) <= self._summary_threshold:
            return session.summary or ""

        # Split: messages to summarise vs. messages to keep
        keep_count = self._window_size // 2
        to_summarise = session.messages[:-keep_count]
        to_keep = session.messages[-keep_count:]

        # Build summarisation prompt
        msg_text = "\n".join(
            f"[{type(m).__name__}] {m.content}" for m in to_summarise if hasattr(m, "content")
        )

        summary_prompt = [
            SystemMessage(
                content=(
                    "You are a security analyst assistant. Summarise the following "
                    "conversation history concisely, preserving all critical details: "
                    "indicators of compromise, severity assessments, actions taken, "
                    "and any unresolved items."
                )
            ),
            HumanMessage(
                content=f"Previous summary:\n{session.summary or 'None'}\n\n"
                f"New messages to incorporate:\n{msg_text}"
            ),
        ]

        try:
            result = await llm.ainvoke(summary_prompt)
            new_summary = result.content if hasattr(result, "content") else str(result)
        except Exception:
            logger.warning("Session summarisation failed", exc_info=True)
            new_summary = session.summary or ""

        # Update session
        session.summary = new_summary
        session.messages = to_keep
        session.updated_at = datetime.now()
        logger.info(
            "Session %s summarised: %d msgs → %d msgs + summary",
            session_id,
            len(to_summarise) + len(to_keep),
            len(to_keep),
        )

        return new_summary

    def delete_session(self, session_id: str) -> bool:
        """Remove a session from the store."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return metadata for all active sessions."""
        return [
            {
                "session_id": s.session_id,
                "message_count": len(s.messages),
                "has_summary": bool(s.summary),
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat(),
            }
            for s in self._sessions.values()
        ]


class SessionData:
    """Container for a single session's data."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.messages: list[BaseMessage] = []
        self.summary: str = ""
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.metadata: dict[str, Any] = {}


# ═══════════════════════════════════════════════════════════════
#  Alert Store (TUI & API dashboard feed)
# ═══════════════════════════════════════════════════════════════


class AlertRecord:
    """Historical record of an alert and its triage resolution."""

    def __init__(
        self,
        alert_id: str,
        session_id: str,
        source: str,
        raw_alert: str,
        severity: str = "UNKNOWN",
        status: str = "IN_PROGRESS",
        final_response: str = "",
        iocs: list[str] | None = None,
        message_count: int = 0,
        duration_seconds: float = 0.0,
        error: str | None = None,
    ) -> None:
        self.alert_id = alert_id
        self.session_id = session_id
        self.source = source
        self.raw_alert = raw_alert
        self.severity = severity
        self.status = status  # IN_PROGRESS, COMPLETED, FAILED
        self.final_response = final_response
        self.iocs = iocs or []
        self.message_count = message_count
        self.duration_seconds = duration_seconds
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "session_id": self.session_id,
            "source": self.source,
            "raw_alert": self.raw_alert,
            "severity": self.severity,
            "status": self.status,
            "final_response": self.final_response,
            "iocs": self.iocs,
            "message_count": self.message_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "error": self.error,
        }


class AlertStore:
    """In-memory store for recent alert records."""

    def __init__(self, max_history: int = 100) -> None:
        self._max_history = max_history
        self._alerts: list[AlertRecord] = []
        self._by_id: dict[str, AlertRecord] = {}

    def record_alert(
        self,
        alert_id: str,
        session_id: str,
        source: str,
        raw_alert: str,
    ) -> AlertRecord:
        record = AlertRecord(
            alert_id=alert_id,
            session_id=session_id,
            source=source,
            raw_alert=raw_alert,
        )
        self._alerts.insert(0, record)
        self._by_id[alert_id] = record
        self._by_id[session_id] = record
        if len(self._alerts) > self._max_history:
            oldest = self._alerts.pop()
            self._by_id.pop(oldest.alert_id, None)
            self._by_id.pop(oldest.session_id, None)
        return record

    def update_alert(
        self,
        alert_id_or_session: str,
        *,
        severity: str | None = None,
        status: str = "COMPLETED",
        final_response: str | None = None,
        iocs: list[str] | None = None,
        message_count: int | None = None,
        duration_seconds: float | None = None,
        error: str | None = None,
    ) -> AlertRecord | None:
        record = self._by_id.get(alert_id_or_session)
        if not record:
            return None
        if severity is not None:
            record.severity = severity
        if final_response is not None:
            record.final_response = final_response
        if iocs is not None:
            record.iocs = iocs
        if message_count is not None:
            record.message_count = message_count
        if duration_seconds is not None:
            record.duration_seconds = duration_seconds
        if error is not None:
            record.error = error
        record.status = status
        record.updated_at = datetime.now()
        return record

    def get_alert(self, alert_id_or_session: str) -> AlertRecord | None:
        return self._by_id.get(alert_id_or_session)

    def list_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._alerts[:limit]]


# Global alert store instance
alert_store = AlertStore()
