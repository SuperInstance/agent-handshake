"""Tests for agent_handshake.negotiation."""

import pytest

from agent_handshake.negotiation import AgentCapability, CapabilityNegotiator


class TestAgentCapability:
    def test_create(self):
        cap = AgentCapability(id="telemetry", version="2.1.0", priority=1)
        assert cap.id == "telemetry"
        assert cap.version == "2.1.0"

    def test_major_version(self):
        cap = AgentCapability(id="x", version="3.5.1")
        assert cap.major_version() == 3

    def test_compatible_same_major(self):
        a = AgentCapability(id="tel", version="2.1.0")
        b = AgentCapability(id="tel", version="2.5.0")
        assert a.is_compatible_with(b)

    def test_incompatible_different_major(self):
        a = AgentCapability(id="tel", version="2.0.0")
        b = AgentCapability(id="tel", version="3.0.0")
        assert not a.is_compatible_with(b)

    def test_incompatible_different_id(self):
        a = AgentCapability(id="tel", version="1.0.0")
        b = AgentCapability(id="exec", version="1.0.0")
        assert not a.is_compatible_with(b)

    def test_serialization(self):
        cap = AgentCapability(id="x", version="1.0", priority=5, description="test")
        d = cap.to_dict()
        restored = AgentCapability.from_dict(d)
        assert restored == cap

    def test_empty_id_raises(self):
        with pytest.raises(ValueError):
            AgentCapability(id="", version="1.0")


class TestCapabilityNegotiator:
    def setup_method(self):
        self.negotiator = CapabilityNegotiator()
        self.local = [
            AgentCapability(id="telemetry", version="2.1.0", priority=1),
            AgentCapability(id="remote_exec", version="1.4.0", priority=2),
            AgentCapability(id="file_transfer", version="1.2.0", priority=3),
        ]

    def test_negotiate_finds_compatibles(self):
        remote = [
            AgentCapability(id="telemetry", version="2.3.0", priority=1),
            AgentCapability(id="remote_exec", version="1.0.0", priority=5),
            AgentCapability(id="unknown", version="1.0.0", priority=0),
        ]
        result = self.negotiator.negotiate(self.local, remote)
        ids = [c.id for c in result]
        assert "telemetry" in ids
        assert "remote_exec" in ids
        assert "unknown" not in ids

    def test_negotiate_no_overlap(self):
        remote = [AgentCapability(id="other", version="1.0.0")]
        result = self.negotiator.negotiate(self.local, remote)
        assert len(result) == 0

    def test_negotiate_sorted_by_priority(self):
        remote = [
            AgentCapability(id="telemetry", version="2.0.0", priority=1),
            AgentCapability(id="file_transfer", version="1.0.0", priority=3),
        ]
        result = self.negotiator.negotiate(self.local, remote)
        assert result[0].priority <= result[-1].priority

    def test_select_protocol_best(self):
        proto = self.negotiator.select_protocol(
            ["hero-v2", "hero-v1"], ["hero-v2", "legacy-encrypted"]
        )
        assert proto == "hero-v2"

    def test_select_protocol_fallback(self):
        proto = self.negotiator.select_protocol(
            ["legacy-encrypted"], ["hero-v2", "legacy-encrypted"]
        )
        assert proto == "legacy-encrypted"

    def test_select_protocol_no_common(self):
        proto = self.negotiator.select_protocol(["a"], ["b"])
        assert proto == ""

    def test_get_incompatible(self):
        remote = [AgentCapability(id="telemetry", version="2.0.0")]
        incompatible = self.negotiator.get_incompatible(self.local, remote)
        ids = [c.id for c in incompatible]
        assert "telemetry" not in ids
        assert "remote_exec" in ids
        assert "file_transfer" in ids
