"""Tests for agent_handshake.session."""

import time

from agent_handshake.negotiation import AgentCapability
from agent_handshake.session import Session, SessionManager


def _make_caps() -> list[AgentCapability]:
    return [AgentCapability(id="tel", version="1.0")]


class TestSession:
    def test_create(self):
        s = Session(
            session_id="abc",
            agent_id="agent-1",
            trust_score=75.0,
            protocol="hero-v2",
            capabilities=_make_caps(),
        )
        assert s.session_id == "abc"
        assert s.is_valid()

    def test_expiry(self):
        s = Session(
            session_id="abc",
            agent_id="agent-1",
            trust_score=75.0,
            protocol="hero-v2",
            capabilities=[],
            expires_at=time.time() - 10,
        )
        assert not s.is_valid()

    def test_remaining_seconds(self):
        s = Session(
            session_id="abc",
            agent_id="agent-1",
            trust_score=75.0,
            protocol="hero-v2",
            capabilities=[],
            expires_at=time.time() + 100,
        )
        assert 90 < s.remaining_seconds() <= 100

    def test_to_dict(self):
        s = Session(
            session_id="abc",
            agent_id="agent-1",
            trust_score=75.0,
            protocol="hero-v2",
            capabilities=_make_caps(),
        )
        d = s.to_dict()
        assert d["session_id"] == "abc"
        assert d["trust_score"] == 75.0
        assert len(d["capabilities"]) == 1


class TestSessionManager:
    def test_create_and_get(self):
        mgr = SessionManager()
        s = mgr.create_session("agent-1", 80.0, "hero-v2", _make_caps())
        assert s.agent_id == "agent-1"
        retrieved = mgr.get_session(s.session_id)
        assert retrieved is not None
        assert retrieved.session_id == s.session_id

    def test_validate(self):
        mgr = SessionManager()
        s = mgr.create_session("agent-1", 80.0, "hero-v2", [])
        assert mgr.validate_session(s.session_id)
        assert not mgr.validate_session("nonexistent")

    def test_revoke(self):
        mgr = SessionManager()
        s = mgr.create_session("agent-1", 80.0, "hero-v2", [])
        assert mgr.revoke_session(s.session_id)
        assert not mgr.validate_session(s.session_id)
        assert not mgr.revoke_session(s.session_id)

    def test_active_sessions(self):
        mgr = SessionManager()
        mgr.create_session("a", 80.0, "hero-v2", [])
        mgr.create_session("b", 70.0, "hero-v1", [])
        assert len(mgr.active_sessions()) == 2

    def test_cleanup_expired(self):
        mgr = SessionManager(session_duration=-1)  # immediately expired
        mgr.create_session("a", 80.0, "hero-v2", [])
        assert mgr.cleanup_expired() == 1
        assert len(mgr.active_sessions()) == 0
