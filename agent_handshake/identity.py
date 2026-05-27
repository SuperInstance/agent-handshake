"""Agent identity verification and trust scoring."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentIdentity:
    """Represents an agent's identity and metadata."""

    agent_id: str
    public_key: str
    name: str = ""
    version: str = "1.0.0"
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.agent_id or len(self.agent_id) < 3:
            raise ValueError("agent_id must be at least 3 characters")
        if len(self.agent_id) > 64:
            raise ValueError("agent_id must be at most 64 characters")
        if not self.public_key:
            raise ValueError("public_key is required")

    def fingerprint(self) -> str:
        """Return a deterministic fingerprint for this identity."""
        raw = f"{self.agent_id}:{self.public_key}:{self.version}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "name": self.name,
            "version": self.version,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentIdentity:
        return cls(
            agent_id=data["agent_id"],
            public_key=data["public_key"],
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", time.time()),
        )


@dataclass
class TrustRecord:
    """Tracks trust history for an agent across handshakes."""

    agent_id: str
    trust_score: float = 50.0
    handshake_count: int = 0
    last_seen: float = field(default_factory=time.time)
    flags: list[str] = field(default_factory=list)

    def record_handshake(self, success: bool) -> None:
        self.handshake_count += 1
        self.last_seen = time.time()
        if success:
            # Reward: up to +5, diminishing with trust
            delta = max(0.5, 5.0 - (self.trust_score / 25.0))
            self.trust_score = min(100.0, self.trust_score + delta)
        else:
            # Penalty: -10 minimum
            self.trust_score = max(0.0, self.trust_score - 10.0)

    def is_trusted(self, threshold: float = 60.0) -> bool:
        return self.trust_score >= threshold

    def add_flag(self, flag: str) -> None:
        if flag not in self.flags:
            self.flags.append(flag)
            self.trust_score = max(0.0, self.trust_score - 5.0)


class TrustManager:
    """Manages trust records for multiple agents."""

    def __init__(self) -> None:
        self._records: dict[str, TrustRecord] = {}

    def get_or_create(self, agent_id: str) -> TrustRecord:
        if agent_id not in self._records:
            self._records[agent_id] = TrustRecord(agent_id=agent_id)
        return self._records[agent_id]

    def calculate_trust(
        self,
        identity: AgentIdentity,
        capabilities: list[dict[str, Any]],
    ) -> float:
        """Calculate a trust score for an agent based on identity and capabilities."""
        record = self.get_or_create(identity.agent_id)
        score = record.trust_score

        # Bonus for trusted prefix
        if identity.agent_id.startswith("trusted-"):
            score = min(100.0, score + 20.0)

        # Bonus for capability count
        if len(capabilities) >= 3:
            score = min(100.0, score + 15.0)

        # Bonus for health_monitoring capability (shows transparency)
        if any(c.get("id") == "health_monitoring" for c in capabilities):
            score = min(100.0, score + 10.0)

        return min(100.0, score)

    def get_record(self, agent_id: str) -> TrustRecord | None:
        return self._records.get(agent_id)

    def all_records(self) -> dict[str, TrustRecord]:
        return dict(self._records)
