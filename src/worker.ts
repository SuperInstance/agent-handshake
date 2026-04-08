interface AgentCapability {
  id: string;
  version: string;
  priority: number;
  description: string;
}

interface HandshakeRequest {
  agentId: string;
  publicKey: string;
  supportedProtocols: string[];
  capabilities: AgentCapability[];
  timestamp: number;
  signature?: string;
}

interface NegotiationRequest {
  agentId: string;
  selectedProtocol: string;
  requiredCapabilities: string[];
  optionalCapabilities: string[];
}

interface HandshakeResponse {
  sessionId: string;
  serverPublicKey: string;
  selectedProtocol: string;
  compatibleCapabilities: AgentCapability[];
  trustLevel: number;
  expiresAt: number;
}

interface CapabilitiesResponse {
  serverCapabilities: AgentCapability[];
  supportedProtocols: string[];
  minAgentVersion: string;
  maxAgentVersion: string;
}

const SERVER_CAPABILITIES: AgentCapability[] = [
  { id: "telemetry", version: "2.1.0", priority: 1, description: "Telemetry data collection" },
  { id: "remote_exec", version: "1.4.0", priority: 2, description: "Remote command execution" },
  { id: "file_transfer", version: "1.2.0", priority: 3, description: "Secure file transfer" },
  { id: "config_management", version: "1.0.0", priority: 4, description: "Configuration management" },
  { id: "health_monitoring", version: "1.3.0", priority: 5, description: "System health monitoring" }
];

const SUPPORTED_PROTOCOLS = ["hero-v2", "hero-v1", "legacy-encrypted", "legacy-plain"];
const DEFAULT_PROTOCOL = "hero-v2";
const SESSION_DURATION = 3600;

class SessionManager {
  private sessions = new Map<string, { expiresAt: number; agentId: string; trustLevel: number }>();

  createSession(agentId: string, trustLevel: number): string {
    const sessionId = crypto.randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DURATION;
    this.sessions.set(sessionId, { expiresAt, agentId, trustLevel });
    this.cleanupExpiredSessions();
    return sessionId;
  }

  validateSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (session.expiresAt < Math.floor(Date.now() / 1000)) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  private cleanupExpiredSessions() {
    const now = Math.floor(Date.now() / 1000);
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(sessionId);
      }
    }
  }
}

const sessionManager = new SessionManager();

function generateKeyPair(): { publicKey: string; privateKey: string } {
  const publicKey = btoa(crypto.randomUUID().replace(/-/g, '')).slice(0, 32);
  const privateKey = btoa(crypto.randomUUID().replace(/-/g, '')).slice(0, 32);
  return { publicKey, privateKey };
}

function calculateTrustLevel(agentId: string, capabilities: AgentCapability[]): number {
  let trust = 50;
  if (agentId.startsWith("trusted-")) trust += 20;
  if (capabilities.length >= 3) trust += 15;
  if (capabilities.some(c => c.id === "health_monitoring")) trust += 10;
  return Math.min(trust, 100);
}

function findCompatibleCapabilities(agentCapabilities: AgentCapability[]): AgentCapability[] {
  return SERVER_CAPABILITIES.filter(serverCap => 
    agentCapabilities.some(agentCap => 
      agentCap.id === serverCap.id && 
      agentCap.version >= serverCap.version.split('.')[0]
    )
  ).sort((a, b) => b.priority - a.priority);
}

function selectProtocol(supportedProtocols: string[]): string {
  for (const protocol of SUPPORTED_PROTOCOLS) {
    if (supportedProtocols.includes(protocol)) {
      return protocol;
    }
  }
  return DEFAULT_PROTOCOL;
}

function validateHandshakeRequest(req: HandshakeRequest): boolean {
  if (!req.agentId || req.agentId.length < 3 || req.agentId.length > 64) return false;
  if (!req.publicKey || req.publicKey.length !== 32) return false;
  if (!Array.isArray(req.supportedProtocols) || req.supportedProtocols.length === 0) return false;
  if (!Array.isArray(req.capabilities)) return false;
  if (typeof req.timestamp !== 'number') return false;
  if (Math.abs(Date.now() - req.timestamp) > 30000) return false;
  return true;
}

function htmlResponse(content: string, status = 200): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hero Agent Handshake</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --dark: #0a0a0f; --accent: #dc2626; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Inter', sans-serif; 
      background: var(--dark); 
      color: #e5e7eb; 
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .container { 
      max-width: 1200px; 
      margin: 0 auto; 
      padding: 2rem; 
      flex: 1;
    }
    header { 
      border-bottom: 1px solid #1f2937; 
      padding-bottom: 1.5rem; 
      margin-bottom: 2rem; 
    }
    h1 { 
      font-size: 2.5rem; 
      font-weight: 700; 
      color: white; 
      margin-bottom: 0.5rem; 
    }
    .accent { color: var(--accent); }
    .subtitle { 
      font-size: 1.1rem; 
      color: #9ca3af; 
      margin-bottom: 2rem; 
    }
    .endpoint { 
      background: #111827; 
      border: 1px solid #374151; 
      border-radius: 0.5rem; 
      padding: 1.5rem; 
      margin-bottom: 1.5rem; 
    }
    .method { 
      display: inline-block; 
      background: var(--accent); 
      color: white; 
      padding: 0.25rem 0.75rem; 
      border-radius: 0.25rem; 
      font-weight: 600; 
      margin-right: 1rem; 
    }
    .path { 
      font-family: monospace; 
      color: #60a5fa; 
      font-size: 1.1rem; 
    }
    .description { 
      margin-top: 0.75rem; 
      color: #d1d5db; 
      line-height: 1.6; 
    }
    footer { 
      background: #111827; 
      border-top: 1px solid #1f2937; 
      padding: 2rem; 
      text-align: center; 
      color: #9ca3af; 
      font-size: 0.9rem; 
    }
    .footer-links { 
      margin-top: 1rem; 
    }
    .footer-links a { 
      color: #d1d5db; 
      text-decoration: none; 
      margin: 0 1rem; 
    }
    .footer-links a:hover { 
      color: var(--accent); 
      text-decoration: underline; 
    }
    .status { 
      display: inline-block; 
      padding: 0.25rem 0.75rem; 
      background: #065f46; 
      color: #a7f3d0; 
      border-radius: 9999px; 
      font-size: 0.875rem; 
      font-weight: 500; 
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Hero <span class="accent">Agent Handshake</span></h1>
      <p class="subtitle">Protocol for fleet agents to discover and negotiate capabilities</p>
    </header>
    
    <main>
      <div class="endpoint">
        <div><span class="method">POST</span> <span class="path">/api/handshake</span></div>
        <p class="description">Establish trust and create a new session with capability advertisement.</p>
      </div>
      
      <div class="endpoint">
        <div><span class="method">GET</span> <span class="path">/api/capabilities</span></div>
        <p class="description">Discover server capabilities and supported protocol versions.</p>
      </div>
      
      <div class="endpoint">
        <div><span class="method">POST</span> <span class="path">/api/negotiate</span></div>
        <p class="description">Negotiate protocol and capabilities for graceful degradation.</p>
      </div>
      
      <div class="endpoint">
        <div><span class="method">GET</span> <span class="path">/health</span> <span class="status">OK</span></div>
        <p class="description">Health check endpoint for load balancers and monitoring.</p>
      </div>
    </main>
  </div>
  
  <footer>
    <div>Hero Agent Fleet &copy; ${new Date().getFullYear()}</div>
    <div class="footer-links">
      <a href="/api/capabilities">Capabilities</a>
      <a href="/health">Health</a>
      <a href="https://developers.cloudflare.com/workers/">Documentation</a>
    </div>
  </footer>
</body>
</html>`;
  
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'none';"
    }
  });
}

async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/' || path === '') {
    return htmlResponse('');
  }

  if (path === '/health') {
    return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (path === '/api/capabilities') {
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const response: CapabilitiesResponse = {
      serverCapabilities: SERVER_CAPABILITIES,
      supportedProtocols: SUPPORTED_PROTOCOLS,
      minAgentVersion: "1.0.0",
      maxAgentVersion: "3.0.0"
    };

    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (path === '/api/handshake') {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const handshakeReq = await request.json() as HandshakeRequest;
      
      if (!validateHandshakeRequest(handshakeReq)) {
        return new Response(JSON.stringify({ error: 'Invalid handshake request' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const trustLevel = calculateTrustLevel(handshakeReq.agentId, handshakeReq.capabilities);
      const compatibleCaps = findCompatibleCapabilities(handshakeReq.capabilities);
      const selectedProtocol = selectProtocol(handshakeReq.supportedProtocols);
      const sessionId = sessionManager.createSession(handshakeReq.agentId, trustLevel);
      const keyPair = generateKeyPair();

      const response: HandshakeResponse = {
        sessionId,
        serverPublicKey: keyPair.publicKey,
        selectedProtocol,
        compatibleCapabilities: compatibleCaps,
        trustLevel,
        expiresAt: Math.floor(Date.now() / 1000) + SESSION_DURATION
      };

      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  if (path === '/api/negotiate') {
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const negotiateReq = await request.json() as NegotiationRequest;
      
      if (!negotiateReq.agentId || !negotiateReq.selectedProtocol) {
        return new Response(JSON.stringify({ error: 'Missing required fields' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      if (!SUPPORTED_PROTOCOLS.includes(negotiateReq.selectedProtocol)) {
        return new Response(JSON.stringify({ 
          error: 'Unsupported protocol',
          fallbackProtocol: DEFAULT_PROTOCOL 
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const availableCaps = SERVER_CAPABILITIES.filter(cap => 
        negotiateReq.requiredCapabilities.includes(cap.id) ||
        negotiateReq.optionalCapabilities.includes(cap.id)
      );

      return new Response(JSON.stringify({
        negotiatedProtocol: negotiateReq.selectedProtocol,
        grantedCapabilities: availableCaps,
        sessionRequired: true
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  return new Response(JSON.stringify({ error: 'Not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
}

export default {
  async fetch(request: Request): Promise<Response> {
    return handleRequest(request);
  }
};