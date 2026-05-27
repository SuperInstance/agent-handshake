"""Tests for agent_handshake.identity."""

import time

from agent_handshake.identity import AgentIdentity, TrustManager, TrustRecord


class TestAgentIdentity:
    def test_create_basic(self):
        agent = AgentIdentity(agent_id="test-agent", public_key="abc123")
        assert agent.agent_id == "test-agent"
        assert agent.public_key == "abc123"
        assert agent.version == "1.0.0"

    def test_invalid_short_id(self):
        import pytest
        with pytest.raises(ValueError, match="at least 3"):
            AgentIdentity(agent_id="ab", public_key="key")

    def test_invalid_long_id(self):
        import pytest
        with pytest.raises(ValueError, match="at most 64"):
            AgentIdentity(agent_id="x" * 65, public_key="key")

    def test_invalid_empty_key(self):
        import pytest
        with pytest.raises(ValueError, match="public_key"):
            AgentIdentity(agent_id="agent", public_key="")

    def test_fingerprint_deterministic(self):
        a = AgentIdentity(agent_id="abc", public_key="k", version="1.0")
        b = AgentIdentity(agent_id="abc", public_key="k", version="1.0")
        assert a.fingerprint() == b.fingerprint()

    def test_fingerprint_differs(self):
        a = AgentIdentity(agent_id="abc", public_key="k1")
        b = AgentIdentity(agent_id="abc", public_key="k2")
        assert a.fingerprint() != b.fingerprint()

    def test_serialization_roundtrip(self):
        agent = AgentIdentity(
            agent_id="my-agent",
            public_key="pk-123",
            name="Test Agent",
            version="2.0.0",
            metadata={"env": "prod"},
        )
        d = agent.to_dict()
        restored = AgentIdentity.from_dict(d)
        assert restored.agent_id == agent.agent_id
        assert restored.public_key == agent.public_key
        assert restored.name == agent.name
        assert restored.version == agent.version
        assert restored.metadata == agent.metadata


class TestTrustRecord:
    def test_initial_score(self):
        rec = TrustRecord(agent_id="a")
        assert rec.trust_score == 50.0
        assert rec.handshake_count == 0

    def test_successful_handshake_increases(self):
        rec = TrustRecord(agent_id="a")
        rec.record_handshake(success=True)
        assert rec.trust_score > 50.0
        assert rec.handshake_count == 1

    def test_failed_handshake_decreases(self):
        rec = TrustRecord(agent_id="a")
        rec.record_handshake(success=False)
        assert rec.trust_score == 40.0
        assert rec.handshake_count == 1

    def test_is_trusted(self):
        rec = TrustRecord(agent_id="a", trust_score=70)
        assert rec.is_trusted()
        assert not rec.is_trusted(threshold=80)

    def test_add_flag(self):
        rec = TrustRecord(agent_id="a")
        rec.add_flag("suspicious")
        assert "suspicious" in rec.flags
        assert rec.trust_score == 45.0

    def test_no_duplicate_flag(self):
        rec = TrustRecord(agent_id="a")
        rec.add_flag("x")
        rec.add_flag("x")
        assert rec.flags.count("x") == 1
        assert rec.trust_score == 45.0  # only penalized once


class TestTrustManager:
    def test_get_or_create(self):
        mgr = TrustManager()
        rec = mgr.get_or_create("agent-1")
        assert rec.agent_id == "agent-1"
        assert rec.trust_score == 50.0

    def test_same_record_returned(self):
        mgr = TrustManager()
        r1 = mgr.get_or_create("a")
        r2 = mgr.get_or_create("a")
        assert r1 is r2

    def test_trusted_prefix_bonus(self):
        mgr = TrustManager()
        identity = AgentIdentity(agent_id="trusted-agent", public_key="pk")
        score = mgr.calculate_trust(identity, [])
        assert score >= 70.0

    def test_capability_bonus(self):
        mgr = TrustManager()
        identity = AgentIdentity(agent_id="agent", public_key="pk")
        caps = [
            {"id": "telemetry", "version": "1.0"},
            {"id": "remote_exec", "version": "1.0"},
            {"id": "health_monitoring", "version": "1.0"},
        ]
        score = mgr.calculate_trust(identity, caps)
        assert score >= 75.0  # 50 base + 15 (3+ caps) + 10 (health_monitoring)
