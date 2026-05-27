# agent-handshake

Secure agent handshake protocol — introduction, capability negotiation, and trust scoring between autonomous agents.

Part of the [SuperInstance](https://github.com/SuperInstance) fleet.

## Install

```bash
pip install agent-handshake
```

## Quick Start

```python
from agent_handshake import (
    AgentIdentity,
    HandshakeProtocol,
    AgentCapability,
)

# Define who you are
identity = AgentIdentity(
    agent_id="my-agent",
    public_key="pk-abc123",
    version="2.0.0",
)

# Advertise capabilities
capabilities = [
    AgentCapability(id="telemetry", version="2.1.0", priority=1, description="Telemetry collection"),
    AgentCapability(id="remote_exec", version="1.4.0", priority=2, description="Remote execution"),
]

# Create the protocol state machine
protocol = HandshakeProtocol(identity, capabilities)

# --- Initiator side ---
hello = protocol.send_hello()
# Send `hello` to the remote agent...

# --- Responder side ---
remote_protocol = HandshakeProtocol(remote_identity, remote_capabilities)
challenge = remote_protocol.receive_hello(hello)

# Client responds
response = protocol.respond_to_challenge(challenge)

# Server verifies and negotiates
remote_protocol.verify_challenge(response)
compatible = remote_protocol.exchange_capabilities(
    [c.to_dict() for c in capabilities],
    ["hero-v2"],
)

# Finalize
result = remote_protocol.finalize()
assert result.is_success()
print(f"Session: {result.session_id}, Trust: {result.trust_score}")
```

## Modules

| Module | Description |
|---|---|
| `protocol` | Handshake state machine (HELLO → AUTH → CAPABILITIES → READY → ESTABLISHED) |
| `identity` | Agent identity, fingerprints, and trust scoring |
| `negotiation` | Capability matching and protocol selection |
| `session` | Session lifecycle management |
| `security` | Challenge-response authentication |

## Handshake States

```
HELLO ──► AUTH ──► CAPABILITIES ──► READY ──► ESTABLISHED
  │          │           │              │
  └──────────┴───────────┴──────────────┘──► FAILED
```

## License

MIT
