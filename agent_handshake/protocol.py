"""Handshake protocol state machine."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_handshake.identity import AgentIdentity, TrustManager
from agent_handshake.negotiation import CapabilityNegotiator, AgentCapability
from agent_handshake.security import ChallengeResponseAuth
from agent_handshake.session import Session, SessionManager


class HandshakeState(enum.Enum):
    """States in the handshake protocol."""

    HELLO = "hello"
    AUTH = "auth"
    CAPABILITIES = "capabilities"
    READY = "ready"
    ESTABLISHED = "established"
    FAILED = "failed"


@dataclass
class HandshakeResult:
    """Result of a completed handshake."""

    session_id: str
    state: HandshakeState
    local_identity: AgentIdentity
    remote_identity: AgentIdentity
    selected_protocol: str
    compatible_capabilities: list[AgentCapability]
    trust_score: float
    negotiated_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_success(self) -> bool:
        return self.state == HandshakeState.ESTABLISHED

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "local_identity": self.local_identity.to_dict(),
            "remote_identity": self.remote_identity.to_dict(),
            "selected_protocol": self.selected_protocol,
            "compatible_capabilities": [c.to_dict() for c in self.compatible_capabilities],
            "trust_score": self.trust_score,
            "negotiated_at": self.negotiated_at,
            "metadata": self.metadata,
        }


class HandshakeProtocol:
    """State machine for the agent handshake protocol.

    Usage::

        protocol = HandshakeProtocol(local_identity, capabilities, protocols)
        # Step through: HELLO -> AUTH -> CAPABILITIES -> READY -> ESTABLISHED
        protocol.send_hello()
        protocol.verify_challenge(response)
        protocol.exchange_capabilities(remote_caps, remote_protocols)
        result = protocol.finalize()
    """

    SUPPORTED_PROTOCOLS = ["hero-v2", "hero-v1", "legacy-encrypted", "legacy-plain"]
    DEFAULT_PROTOCOL = "hero-v2"

    def __init__(
        self,
        local_identity: AgentIdentity,
        local_capabilities: list[AgentCapability],
        supported_protocols: list[str] | None = None,
        *,
        trust_manager: TrustManager | None = None,
        session_manager: SessionManager | None = None,
    ) -> None:
        self.local_identity = local_identity
        self.local_capabilities = local_capabilities
        self.supported_protocols = supported_protocols or list(self.SUPPORTED_PROTOCOLS)

        self._state = HandshakeState.HELLO
        self._trust_manager = trust_manager or TrustManager()
        self._session_manager = session_manager or SessionManager()
        self._negotiator = CapabilityNegotiator()
        self._auth = ChallengeResponseAuth()

        self._remote_identity: AgentIdentity | None = None
        self._remote_capabilities: list[AgentCapability] = []
        self._remote_protocols: list[str] = []
        self._selected_protocol: str = ""
        self._compatible_capabilities: list[AgentCapability] = []
        self._trust_score: float = 0.0
        self._session: Session | None = None

    @property
    def state(self) -> HandshakeState:
        return self._state

    def send_hello(self) -> dict[str, Any]:
        """Initiate handshake (HELLO state). Returns the hello message."""
        if self._state != HandshakeState.HELLO:
            raise RuntimeError(f"Expected HELLO state, got {self._state.value}")
        self._state = HandshakeState.AUTH
        return {
            "type": "hello",
            "agent_id": self.local_identity.agent_id,
            "public_key": self.local_identity.public_key,
            "version": self.local_identity.version,
            "supported_protocols": self.supported_protocols,
            "capabilities": [c.to_dict() for c in self.local_capabilities],
            "timestamp": time.time(),
        }

    def receive_hello(self, hello: dict[str, Any]) -> dict[str, Any]:
        """Process an incoming hello and return a challenge."""
        if self._state != HandshakeState.HELLO:
            raise RuntimeError(f"Expected HELLO state, got {self._state.value}")

        remote_id = hello.get("agent_id", "")
        remote_pk = hello.get("public_key", "")
        if not remote_id or not remote_pk:
            self._state = HandshakeState.FAILED
            raise ValueError("Invalid hello: missing agent_id or public_key")

        self._remote_identity = AgentIdentity(
            agent_id=remote_id,
            public_key=remote_pk,
            version=hello.get("version", "1.0.0"),
        )
        self._remote_protocols = hello.get("supported_protocols", [])
        self._remote_capabilities = [
            AgentCapability.from_dict(c) for c in hello.get("capabilities", [])
        ]

        self._state = HandshakeState.AUTH
        return self._auth.generate_challenge(self._remote_identity)

    def verify_challenge(self, response: dict[str, Any]) -> bool:
        """Verify the challenge response (AUTH state)."""
        if self._state != HandshakeState.AUTH:
            raise RuntimeError(f"Expected AUTH state, got {self._state.value}")

        if not self._auth.verify_response(response):
            self._state = HandshakeState.FAILED
            return False

        self._state = HandshakeState.CAPABILITIES
        return True

    def respond_to_challenge(self, challenge: dict[str, Any]) -> dict[str, Any]:
        """Generate a response to a challenge (AUTH state, client side)."""
        if self._state != HandshakeState.AUTH:
            raise RuntimeError(f"Expected AUTH state, got {self._state.value}")
        return self._auth.respond_to_challenge(self.local_identity, challenge)

    def exchange_capabilities(
        self,
        remote_caps: list[dict[str, Any]],
        remote_protocols: list[str],
    ) -> list[AgentCapability]:
        """Exchange and negotiate capabilities (CAPABILITIES state)."""
        if self._state != HandshakeState.CAPABILITIES:
            raise RuntimeError(f"Expected CAPABILITIES state, got {self._state.value}")

        parsed_caps = [AgentCapability.from_dict(c) for c in remote_caps]
        self._compatible_capabilities = self._negotiator.negotiate(
            self.local_capabilities, parsed_caps
        )
        self._selected_protocol = self._negotiator.select_protocol(
            self.supported_protocols, remote_protocols
        )

        self._state = HandshakeState.READY
        return self._compatible_capabilities

    def finalize(self) -> HandshakeResult:
        """Finalize the handshake, creating a session (READY -> ESTABLISHED)."""
        if self._state != HandshakeState.READY:
            raise RuntimeError(f"Expected READY state, got {self._state.value}")

        if self._remote_identity is None:
            self._state = HandshakeState.FAILED
            raise RuntimeError("No remote identity set")

        self._trust_score = self._trust_manager.calculate_trust(
            self._remote_identity,
            [c.to_dict() for c in self._remote_capabilities],
        )

        # Record the handshake
        record = self._trust_manager.get_or_create(self._remote_identity.agent_id)
        record.record_handshake(success=True)

        self._session = self._session_manager.create_session(
            agent_id=self._remote_identity.agent_id,
            trust_score=self._trust_score,
            protocol=self._selected_protocol,
            capabilities=self._compatible_capabilities,
        )

        self._state = HandshakeState.ESTABLISHED
        return HandshakeResult(
            session_id=self._session.session_id,
            state=self._state,
            local_identity=self.local_identity,
            remote_identity=self._remote_identity,
            selected_protocol=self._selected_protocol,
            compatible_capabilities=self._compatible_capabilities,
            trust_score=self._trust_score,
        )

    def fail(self, reason: str = "") -> None:
        """Force the handshake into FAILED state."""
        self._state = HandshakeState.FAILED
        if self._remote_identity:
            record = self._trust_manager.get_or_create(self._remote_identity.agent_id)
            record.record_handshake(success=False)
