"""
agent-handshake — Secure agent handshake protocol.

Provides introduction, capability negotiation, and trust scoring
between autonomous agents.
"""

from agent_handshake.identity import AgentIdentity
from agent_handshake.protocol import HandshakeState, HandshakeResult
from agent_handshake.session import Session, SessionManager
from agent_handshake.negotiation import CapabilityNegotiator
from agent_handshake.security import ChallengeResponseAuth

__all__ = [
    "AgentIdentity",
    "HandshakeState",
    "HandshakeResult",
    "Session",
    "SessionManager",
    "CapabilityNegotiator",
    "ChallengeResponseAuth",
]
__version__ = "0.1.0"
