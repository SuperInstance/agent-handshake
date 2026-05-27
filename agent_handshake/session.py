"""Session management after handshake."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_handshake.negotiation import AgentCapability


@dataclass
class Session:
    """Represents an established session between two agents."""

    session_id: str
    agent_id: str
    trust_score: float
    protocol: str
    capabilities: list[AgentCapability]
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + 3600  # 1 hour default

    def is_valid(self) -> bool:
        return time.time() < self.expires_at

    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "trust_score": self.trust_score,
            "protocol": self.protocol,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }


class SessionManager:
    """Manages active sessions."""

    def __init__(self, session_duration: float = 3600.0) -> None:
        self._sessions: dict[str, Session] = {}
        self.session_duration = session_duration

    def create_session(
        self,
        agent_id: str,
        trust_score: float,
        protocol: str,
        capabilities: list[AgentCapability],
    ) -> Session:
        session = Session(
            session_id=uuid.uuid4().hex[:16],
            agent_id=agent_id,
            trust_score=trust_score,
            protocol=protocol,
            capabilities=capabilities,
            expires_at=time.time() + self.session_duration,
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session and not session.is_valid():
            del self._sessions[session_id]
            return None
        return session

    def validate_session(self, session_id: str) -> bool:
        return self.get_session(session_id) is not None

    def revoke_session(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def active_sessions(self) -> list[Session]:
        now = time.time()
        expired = [sid for sid, s in self._sessions.items() if s.expires_at < now]
        for sid in expired:
            del self._sessions[sid]
        return list(self._sessions.values())

    def cleanup_expired(self) -> int:
        now = time.time()
        expired = [sid for sid, s in self._sessions.items() if s.expires_at < now]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)
