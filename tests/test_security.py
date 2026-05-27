"""Tests for agent_handshake.security."""

from agent_handshake.identity import AgentIdentity
from agent_handshake.security import ChallengeResponseAuth


class TestChallengeResponseAuth:
    def test_generate_challenge(self):
        auth = ChallengeResponseAuth()
        identity = AgentIdentity(agent_id="test", public_key="pk-123")
        challenge = auth.generate_challenge(identity)
        assert challenge["type"] == "challenge"
        assert "nonce" in challenge
        assert challenge["agent_id"] == "test"

    def test_respond_to_challenge(self):
        auth = ChallengeResponseAuth()
        identity = AgentIdentity(agent_id="test", public_key="pk-123")
        challenge = auth.generate_challenge(identity)
        response = auth.respond_to_challenge(identity, challenge)
        assert response["type"] == "challenge_response"
        assert response["nonce"] == challenge["nonce"]
        assert "response" in response

    def test_verify_valid_response(self):
        auth = ChallengeResponseAuth()
        identity = AgentIdentity(agent_id="test", public_key="pk-123")
        challenge = auth.generate_challenge(identity)
        response = auth.respond_to_challenge(identity, challenge)
        assert auth.verify_response(response)

    def test_verify_invalid_type(self):
        auth = ChallengeResponseAuth()
        assert not auth.verify_response({"type": "wrong"})

    def test_verify_missing_fields(self):
        auth = ChallengeResponseAuth()
        assert not auth.verify_response({"type": "challenge_response"})
        assert not auth.verify_response({
            "type": "challenge_response",
            "agent_id": "a",
        })

    def test_hash_deterministic(self):
        h1 = ChallengeResponseAuth._compute_hash("pk", "nonce", 1.0)
        h2 = ChallengeResponseAuth._compute_hash("pk", "nonce", 1.0)
        assert h1 == h2

    def test_hash_differs_with_input(self):
        h1 = ChallengeResponseAuth._compute_hash("pk1", "nonce", 1.0)
        h2 = ChallengeResponseAuth._compute_hash("pk2", "nonce", 1.0)
        assert h1 != h2
