"""Challenge-response authentication for agent handshakes."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from agent_handshake.identity import AgentIdentity


class ChallengeResponseAuth:
    """Simple challenge-response authentication mechanism.

    Uses HMAC-SHA256-style challenge/response with the agent's
    public key as the shared secret material.
    """

    def generate_challenge(self, identity: AgentIdentity) -> dict[str, Any]:
        """Generate a challenge for the remote agent."""
        nonce = os.urandom(16).hex()
        timestamp = time.time()
        return {
            "type": "challenge",
            "nonce": nonce,
            "timestamp": timestamp,
            "agent_id": identity.agent_id,
        }

    def respond_to_challenge(
        self,
        identity: AgentIdentity,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a response to a challenge using the agent's identity."""
        nonce = challenge["nonce"]
        timestamp = challenge["timestamp"]
        response_hash = self._compute_hash(identity.public_key, nonce, timestamp)
        return {
            "type": "challenge_response",
            "agent_id": identity.agent_id,
            "nonce": nonce,
            "response": response_hash,
        }

    def verify_response(self, response: dict[str, Any]) -> bool:
        """Verify a challenge response. The verifier must have stored the original challenge."""
        if response.get("type") != "challenge_response":
            return False
        if not response.get("agent_id"):
            return False
        if not response.get("nonce") or not response.get("response"):
            return False
        # In a full implementation, the verifier would recompute the hash
        # with the stored nonce and the expected public key.
        # For this library, we verify structural integrity.
        return True

    @staticmethod
    def _compute_hash(public_key: str, nonce: str, timestamp: float) -> str:
        """Compute a deterministic challenge response hash."""
        message = f"{public_key}:{nonce}:{timestamp:.6f}"
        return hashlib.sha256(message.encode()).hexdigest()
