"""Capability negotiation between agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentCapability:
    """A single capability advertised by an agent."""

    id: str
    version: str
    priority: int = 0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("capability id is required")
        if not self.version:
            raise ValueError("capability version is required")

    def major_version(self) -> int:
        parts = self.version.split(".")
        return int(parts[0]) if parts else 0

    def is_compatible_with(self, other: AgentCapability) -> bool:
        """Check if this capability is compatible with another (same id, same major version)."""
        return self.id == other.id and self.major_version() == other.major_version()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "priority": self.priority,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCapability:
        return cls(
            id=data["id"],
            version=data["version"],
            priority=data.get("priority", 0),
            description=data.get("description", ""),
        )


class CapabilityNegotiator:
    """Negotiates compatible capabilities and protocols between two agents."""

    PROTOCOL_PREFERENCE = ["hero-v2", "hero-v1", "legacy-encrypted", "legacy-plain"]

    def negotiate(
        self,
        local_caps: list[AgentCapability],
        remote_caps: list[AgentCapability],
    ) -> list[AgentCapability]:
        """Find compatible capabilities between local and remote agents.

        Two capabilities are compatible if they share the same id and major version.
        Returns capabilities sorted by descending priority.
        """
        compatible: list[AgentCapability] = []
        for local_cap in local_caps:
            for remote_cap in remote_caps:
                if local_cap.is_compatible_with(remote_cap):
                    # Use the lower-priority-number (higher priority) version
                    chosen = local_cap if local_cap.priority <= remote_cap.priority else remote_cap
                    compatible.append(chosen)
                    break

        compatible.sort(key=lambda c: c.priority)
        return compatible

    def select_protocol(
        self,
        local_protocols: list[str],
        remote_protocols: list[str],
    ) -> str:
        """Select the best mutually-supported protocol."""
        remote_set = set(remote_protocols)
        for proto in self.PROTOCOL_PREFERENCE:
            if proto in local_protocols and proto in remote_set:
                return proto
        # Fallback: any common protocol
        common = set(local_protocols) & remote_set
        if common:
            return next(iter(common))
        return ""

    def get_incompatible(
        self,
        local_caps: list[AgentCapability],
        remote_caps: list[AgentCapability],
    ) -> list[AgentCapability]:
        """Return local capabilities that have no compatible remote counterpart."""
        compatible_ids = set()
        for local_cap in local_caps:
            for remote_cap in remote_caps:
                if local_cap.is_compatible_with(remote_cap):
                    compatible_ids.add(local_cap.id)
                    break
        return [c for c in local_caps if c.id not in compatible_ids]
