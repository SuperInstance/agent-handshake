"""Tests for agent_handshake.protocol."""

import pytest

from agent_handshake.identity import AgentIdentity
from agent_handshake.negotiation import AgentCapability
from agent_handshake.protocol import HandshakeProtocol, HandshakeState, HandshakeResult


def _make_identity(name: str = "test-agent") -> AgentIdentity:
    return AgentIdentity(agent_id=name, public_key=f"pk-{name}")


def _make_caps() -> list[AgentCapability]:
    return [
        AgentCapability(id="telemetry", version="2.1.0", priority=1),
        AgentCapability(id="remote_exec", version="1.4.0", priority=2),
        AgentCapability(id="file_transfer", version="1.2.0", priority=3),
    ]


class TestHandshakeProtocol:
    def test_initial_state_is_hello(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        assert p.state == HandshakeState.HELLO

    def test_send_hello_transitions_to_auth(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        msg = p.send_hello()
        assert msg["type"] == "hello"
        assert msg["agent_id"] == "test-agent"
        assert p.state == HandshakeState.AUTH

    def test_receive_hello(self):
        server = HandshakeProtocol(_make_identity("server"), _make_caps())
        client_hello = {
            "agent_id": "client",
            "public_key": "pk-client",
            "version": "1.0",
            "supported_protocols": ["hero-v2"],
            "capabilities": [{"id": "telemetry", "version": "2.0.0", "priority": 1}],
        }
        challenge = server.receive_hello(client_hello)
        assert challenge["type"] == "challenge"
        assert server.state == HandshakeState.AUTH

    def test_receive_hello_invalid(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        with pytest.raises(ValueError):
            p.receive_hello({"agent_id": "", "public_key": ""})
        assert p.state == HandshakeState.FAILED

    def test_wrong_state_raises(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        with pytest.raises(RuntimeError, match="Expected AUTH"):
            p.verify_challenge({})

    def test_full_handshake_flow(self):
        """Test a complete handshake from HELLO to ESTABLISHED."""
        # Server side
        server = HandshakeProtocol(_make_identity("server"), _make_caps())

        # Client side
        client = HandshakeProtocol(_make_identity("client"), _make_caps())

        # 1. Client sends hello
        hello_msg = client.send_hello()
        assert client.state == HandshakeState.AUTH

        # 2. Server receives hello, generates challenge
        challenge = server.receive_hello(hello_msg)
        assert server.state == HandshakeState.AUTH

        # 3. Client responds to challenge
        response = client.respond_to_challenge(challenge)
        assert client.state == HandshakeState.AUTH

        # 4. Server verifies challenge (structural check)
        assert server.verify_challenge(response)
        assert server.state == HandshakeState.CAPABILITIES

        # 5. Server exchanges capabilities with remote
        compatible = server.exchange_capabilities(
            [c.to_dict() for c in _make_caps()],
            ["hero-v2"],
        )
        assert server.state == HandshakeState.READY
        assert len(compatible) > 0

        # 6. Finalize
        result = server.finalize()
        assert server.state == HandshakeState.ESTABLISHED
        assert result.is_success()
        assert result.session_id
        assert result.trust_score >= 0
        assert result.selected_protocol == "hero-v2"

    def test_finalize_without_ready_fails(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        with pytest.raises(RuntimeError, match="Expected READY"):
            p.finalize()

    def test_fail_method(self):
        p = HandshakeProtocol(_make_identity(), _make_caps())
        p.send_hello()
        p.fail("timeout")
        assert p.state == HandshakeState.FAILED

    def test_result_serialization(self):
        local = _make_identity("local")
        remote = _make_identity("remote")
        result = HandshakeResult(
            session_id="abc123",
            state=HandshakeState.ESTABLISHED,
            local_identity=local,
            remote_identity=remote,
            selected_protocol="hero-v2",
            compatible_capabilities=_make_caps(),
            trust_score=75.0,
        )
        d = result.to_dict()
        assert d["session_id"] == "abc123"
        assert d["state"] == "established"
        assert d["trust_score"] == 75.0
        assert len(d["compatible_capabilities"]) == 3
