/**
 * Guardian — REST API Server
 * ============================================================
 * Exposes Guardian's IAM, zero-trust, token, and sandbox capabilities
 * as a REST API for the Trancendos agent mesh.
 * ============================================================
 * IAM Integration: @trancendos/iam-middleware (HS512 JWT)
 * Security: OWASP, zero-trust, SHA-512 audit, helmet
 * 2060 Standard: Semantic mesh routing, quantum-safe defaults
 * ============================================================
 * Endpoints:
 *   POST   /api/v1/tokens/issue           — Issue agent token
 *   POST   /api/v1/tokens/verify          — Verify agent token
 *   DELETE /api/v1/tokens/:jti            — Revoke token (requireLevel 2)
 *   GET    /api/v1/tokens/history/:agentId — Token history (requireLevel 3)
 *
 *   POST   /api/v1/zero-trust/evaluate    — Evaluate zero-trust request
 *   GET    /api/v1/zero-trust/policies    — List policies (requireLevel 2)
 *   POST   /api/v1/zero-trust/policies    — Create policy (requireLevel 1)
 *   PUT    /api/v1/zero-trust/policies/:id — Update policy (requireLevel 1)
 *   DELETE /api/v1/zero-trust/policies/:id — Delete policy (requireLevel 0)
 *   GET    /api/v1/zero-trust/audit       — Audit log (requireLevel 2)
 *   GET    /api/v1/zero-trust/stats       — Stats
 *
 *   GET    /api/v1/baselines              — All behavioral baselines
 *   GET    /api/v1/baselines/:agentId     — Agent baseline
 *   POST   /api/v1/baselines/:agentId     — Set baseline (requireLevel 3)
 *
 *   GET    /api/v1/sandbox/:agentId       — Get sandbox policy
 *   POST   /api/v1/sandbox/:agentId       — Set sandbox policy (requireLevel 2)
 *   POST   /api/v1/sandbox/:agentId/check — Check sandbox operation
 *
 *   GET    /api/v1/permissions/roles      — List roles + permissions
 *   POST   /api/v1/permissions/check      — Check permission
 *
 *   GET    /health                        — Health check (public)
 *   GET    /metrics                       — Service metrics (requireLevel 3)
 * ============================================================
 * Ticket: TRN-PROD-GUARDIAN-001
 * 2060 Standard: Modular, composable, quantum-safe defaults
 * Revert: 7609026
 */

import express, { Request, Response, NextFunction, Router } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { agentTokenService } from '../tokens/agent-tokens';
import { zeroTrustEngine } from '../zero-trust/zero-trust';
import { permissionChecker, ROLE_PERMISSIONS, AgentPermission } from '../iam/permissions';
import type { ZeroTrustRequest } from '../zero-trust/zero-trust';
import type { UserRole } from '../iam/permissions';

// ============================================================================
// IAM MIDDLEWARE (inline — zero external dependency for guardian-ai)
// Guardian is the security backbone; it validates tokens for others.
// It uses its own lightweight JWT verification to avoid circular dependency.
// ============================================================================

const IAM_JWT_SECRET = process.env.IAM_JWT_SECRET || process.env.JWT_SECRET || '';
const IAM_ALGORITHM = process.env.JWT_ALGORITHM || 'HS512';
const SERVICE_ID = 'guardian-ai';
const MESH_ADDRESS = process.env.MESH_ADDRESS || 'guardian.agent.local';

function sha512(data: string): string {
  return createHash('sha512').update(data).digest('hex');
}

function b64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64').toString('utf8');
}

interface JWTClaims {
  sub: string; email?: string; role?: string;
  active_role_level?: number; permissions?: string[];
  exp?: number; jti?: string;
}

function verifyToken(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const header = JSON.parse(b64urlDecode(h));
    const alg = header.alg === 'HS512' ? 'sha512' : 'sha256';
    const { createHmac } = require('crypto');
    const expected = Buffer.from(
      createHmac(alg, IAM_JWT_SECRET).update(`${h}.${p}`).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    ).toString();
    if (expected !== sig) return null;
    const claims = JSON.parse(b64urlDecode(p)) as JWTClaims;
    if (claims.exp && Date.now() / 1000 > claims.exp) return null;
    return claims;
  } catch { return null; }
}

function requireIAMLevel(maxLevel: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) { res.status(401).json({ error: 'Authentication required', service: SERVICE_ID }); return; }
    const claims = verifyToken(token);
    if (!claims) { res.status(401).json({ error: 'Invalid or expired token', service: SERVICE_ID }); return; }
    const level = claims.active_role_level ?? 6;
    if (level > maxLevel) {
      // SHA-512 audit log for denied access
      logger.warn({
        audit: true,
        decision: 'DENY',
        principal: claims.sub,
        requiredLevel: maxLevel,
        actualLevel: level,
        path: req.path,
        integrityHash: sha512(`DENY:${claims.sub}:${req.path}:${Date.now()}`),
      }, 'IAM level check failed');
      res.status(403).json({ error: 'Insufficient privilege level', required: maxLevel, actual: level });
      return;
    }
    (req as any).principal = claims;
    next();
  };
}

// ============================================================================
// APP SETUP
// ============================================================================

export function createServer(): express.Application {
  const app = express();

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));
  app.use(morgan('combined', {
    stream: { write: (msg: string) => logger.info({ http: msg.trim() }, 'HTTP') },
  }));

  // ============================================================================
  // HEALTH & METRICS
  // ============================================================================

  app.get('/health', (_req: Request, res: Response) => {
    const stats = zeroTrustEngine.getStats();
    res.json({
      status: 'healthy',
      service: SERVICE_ID,
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      policies: stats.policyCount,
      baselines: agentTokenService.getAllBaselines().length,
      revokedTokens: agentTokenService.getRevokedCount(),
      // IAM & 2060 status
      iam: {
        version: '1.0',
        algorithm: IAM_ALGORITHM,
        status: IAM_JWT_SECRET ? 'configured' : 'unconfigured',
        meshAddress: MESH_ADDRESS,
        routingProtocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
        cryptoMigrationPath: 'hmac_sha512 → ml_kem (2030) → hybrid_pqc (2040) → slh_dsa (2060)',
      },
    });
  });

  app.get('/metrics', requireIAMLevel(3), (_req: Request, res: Response) => {
    const ztStats = zeroTrustEngine.getStats();
    const mem = process.memoryUsage();
    res.json({
      service: 'guardian-ai',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: {
        heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
        rssMb: Math.round(mem.rss / 1024 / 1024),
      },
      zeroTrust: ztStats,
      tokens: {
        revoked: agentTokenService.getRevokedCount(),
        baselines: agentTokenService.getAllBaselines().length,
      },
    });
  });

  // ============================================================================
  // TOKEN ROUTES
  // ============================================================================

  // POST /api/v1/tokens/issue
  app.post('/api/v1/tokens/issue', (req: Request, res: Response) => {
    try {
      const { issuerAgentId, targetAgentId, context, permissions, ttlMs } = req.body;

      if (!issuerAgentId || !targetAgentId || !context) {
        return res.status(400).json({ error: 'issuerAgentId, targetAgentId, and context are required' });
      }

      const validation = agentTokenService.validateContextDeclaration(context);
      if (!validation.valid) {
        return res.status(400).json({ error: 'Invalid context declaration', issues: validation.issues });
      }

      const token = agentTokenService.issueToken(
        issuerAgentId,
        targetAgentId,
        context,
        permissions || [],
        ttlMs,
      );

      logger.info({ issuerAgentId, targetAgentId }, 'Token issued via API');
      return res.status(201).json({ token, expiresIn: ttlMs || 500 });
    } catch (err) {
      logger.error({ err }, 'Token issuance failed');
      return res.status(500).json({ error: 'Token issuance failed' });
    }
  });

  // POST /api/v1/tokens/verify
  app.post('/api/v1/tokens/verify', (req: Request, res: Response) => {
    try {
      const { token, expectedTarget } = req.body;
      if (!token) return res.status(400).json({ error: 'token is required' });

      const result = agentTokenService.verifyToken(token, expectedTarget);
      return res.json(result);
    } catch (err) {
      logger.error({ err }, 'Token verification failed');
      return res.status(500).json({ error: 'Token verification failed' });
    }
  });

  // DELETE /api/v1/tokens/:jti — requireLevel 2 (Ops Commander+)
  app.delete('/api/v1/tokens/:jti', requireIAMLevel(2), (req: Request, res: Response) => {
    try {
      const { jti } = req.params;
      agentTokenService.revokeToken(jti);
      logger.info({ jti }, 'Token revoked via API');
      return res.json({ revoked: true, jti });
    } catch (err) {
      logger.error({ err }, 'Token revocation failed');
      return res.status(500).json({ error: 'Token revocation failed' });
    }
  });

  // GET /api/v1/tokens/history/:agentId — requireLevel 3 (Specialist+)
  app.get('/api/v1/tokens/history/:agentId', requireIAMLevel(3), (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const history = agentTokenService.getTokenHistory(agentId);
      return res.json({ agentId, count: history.length, history });
    } catch (err) {
      logger.error({ err }, 'Token history fetch failed');
      return res.status(500).json({ error: 'Failed to fetch token history' });
    }
  });

  // ============================================================================
  // ZERO-TRUST ROUTES
  // ============================================================================

  // POST /api/v1/zero-trust/evaluate
  app.post('/api/v1/zero-trust/evaluate', (req: Request, res: Response) => {
    try {
      const { sourceAgentId, targetAgentId, sourceRole, context, requestedPermissions, ipAddress, sessionId } = req.body;

      if (!sourceAgentId || !targetAgentId || !context) {
        return res.status(400).json({ error: 'sourceAgentId, targetAgentId, and context are required' });
      }

      const request: ZeroTrustRequest = {
        requestId: uuidv4(),
        sourceAgentId,
        targetAgentId,
        sourceRole: (sourceRole as UserRole) || 'agent',
        context,
        requestedPermissions: requestedPermissions || [],
        timestamp: new Date(),
        ipAddress,
        sessionId,
      };

      const decision = zeroTrustEngine.evaluate(request);
      return res.json(decision);
    } catch (err) {
      logger.error({ err }, 'Zero-trust evaluation failed');
      return res.status(500).json({ error: 'Zero-trust evaluation failed' });
    }
  });

  // GET /api/v1/zero-trust/policies — requireLevel 2
  app.get('/api/v1/zero-trust/policies', requireIAMLevel(2), (_req: Request, res: Response) => {
    const policies = zeroTrustEngine.getPolicies();
    return res.json({ count: policies.length, policies });
  });

  // POST /api/v1/zero-trust/policies — requireLevel 1 (Platform Architect+)
  app.post('/api/v1/zero-trust/policies', requireIAMLevel(1), (req: Request, res: Response) => {
    try {
      const { name, description, priority, conditions, action, enabled } = req.body;
      if (!name || !conditions || !action) {
        return res.status(400).json({ error: 'name, conditions, and action are required' });
      }
      const policy = zeroTrustEngine.addPolicy({ name, description, priority: priority || 50, conditions, action, enabled: enabled !== false });
      return res.status(201).json(policy);
    } catch (err) {
      logger.error({ err }, 'Policy creation failed');
      return res.status(500).json({ error: 'Policy creation failed' });
    }
  });

  // PUT /api/v1/zero-trust/policies/:id — requireLevel 1
  app.put('/api/v1/zero-trust/policies/:id', requireIAMLevel(1), (req: Request, res: Response) => {
    try {
      const updated = zeroTrustEngine.updatePolicy(req.params.id, req.body);
      if (!updated) return res.status(404).json({ error: 'Policy not found' });
      return res.json(updated);
    } catch (err) {
      logger.error({ err }, 'Policy update failed');
      return res.status(500).json({ error: 'Policy update failed' });
    }
  });

  // DELETE /api/v1/zero-trust/policies/:id — requireLevel 0 (Continuity Guardian only)
  app.delete('/api/v1/zero-trust/policies/:id', requireIAMLevel(0), (req: Request, res: Response) => {
    const deleted = zeroTrustEngine.deletePolicy(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Policy not found' });
    return res.json({ deleted: true, id: req.params.id });
  });

  // GET /api/v1/zero-trust/audit — requireLevel 2
  app.get('/api/v1/zero-trust/audit', requireIAMLevel(2), (req: Request, res: Response) => {
    try {
      const { sourceAgentId, targetAgentId, action, allowed, limit, since } = req.query;
      const entries = zeroTrustEngine.getAuditLog({
        sourceAgentId: sourceAgentId as string,
        targetAgentId: targetAgentId as string,
        action: action as 'allow' | 'deny' | 'challenge' | 'monitor',
        allowed: allowed !== undefined ? allowed === 'true' : undefined,
        limit: limit ? parseInt(limit as string) : 100,
        since: since ? new Date(since as string) : undefined,
      });
      return res.json({ count: entries.length, entries });
    } catch (err) {
      logger.error({ err }, 'Audit log fetch failed');
      return res.status(500).json({ error: 'Failed to fetch audit log' });
    }
  });

  // GET /api/v1/zero-trust/stats
  app.get('/api/v1/zero-trust/stats', (_req: Request, res: Response) => {
    return res.json(zeroTrustEngine.getStats());
  });

  // ============================================================================
  // BEHAVIORAL BASELINE ROUTES
  // ============================================================================

  // GET /api/v1/baselines
  app.get('/api/v1/baselines', (_req: Request, res: Response) => {
    const baselines = agentTokenService.getAllBaselines();
    return res.json({ count: baselines.length, baselines });
  });

  // GET /api/v1/baselines/:agentId
  app.get('/api/v1/baselines/:agentId', (req: Request, res: Response) => {
    const baseline = agentTokenService.getBaseline(req.params.agentId);
    if (!baseline) return res.status(404).json({ error: 'No baseline found for agent' });
    return res.json(baseline);
  });

  // POST /api/v1/baselines/:agentId — requireLevel 3
  app.post('/api/v1/baselines/:agentId', requireIAMLevel(3), (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const baseline = { agentId, ...req.body };
      agentTokenService.setBaseline(baseline);
      return res.status(201).json({ set: true, agentId });
    } catch (err) {
      logger.error({ err }, 'Baseline set failed');
      return res.status(500).json({ error: 'Failed to set baseline' });
    }
  });

  // POST /api/v1/baselines/:agentId/check
  app.post('/api/v1/baselines/:agentId/check', (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const { requestedCapabilities, targetAgent } = req.body;
      const result = agentTokenService.checkBehavior(agentId, requestedCapabilities || [], targetAgent);
      return res.json(result);
    } catch (err) {
      logger.error({ err }, 'Behavior check failed');
      return res.status(500).json({ error: 'Behavior check failed' });
    }
  });

  // ============================================================================
  // SANDBOX ROUTES
  // ============================================================================

  // GET /api/v1/sandbox/:agentId
  app.get('/api/v1/sandbox/:agentId', (req: Request, res: Response) => {
    const policy = zeroTrustEngine.getSandboxPolicy(req.params.agentId);
    if (!policy) return res.status(404).json({ error: 'No sandbox policy found for agent' });
    return res.json(policy);
  });

  // POST /api/v1/sandbox/:agentId — requireLevel 2
  app.post('/api/v1/sandbox/:agentId', requireIAMLevel(2), (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const policy = { agentId, ...req.body };
      zeroTrustEngine.setSandboxPolicy(policy);
      return res.status(201).json({ set: true, agentId });
    } catch (err) {
      logger.error({ err }, 'Sandbox policy set failed');
      return res.status(500).json({ error: 'Failed to set sandbox policy' });
    }
  });

  // POST /api/v1/sandbox/:agentId/check
  app.post('/api/v1/sandbox/:agentId/check', (req: Request, res: Response) => {
    try {
      const { agentId } = req.params;
      const { operation } = req.body;
      if (!operation) return res.status(400).json({ error: 'operation is required' });
      const result = zeroTrustEngine.checkSandboxOperation(agentId, operation);
      return res.json(result);
    } catch (err) {
      logger.error({ err }, 'Sandbox check failed');
      return res.status(500).json({ error: 'Sandbox check failed' });
    }
  });

  // ============================================================================
  // PERMISSION ROUTES
  // ============================================================================

  // GET /api/v1/permissions/roles
  app.get('/api/v1/permissions/roles', (_req: Request, res: Response) => {
    const roles = Object.entries(ROLE_PERMISSIONS).map(([role, perms]) => ({
      role,
      permissions: perms,
      permissionCount: perms.length,
    }));
    return res.json({ roles, allPermissions: Object.values(AgentPermission) });
  });

  // POST /api/v1/permissions/check
  app.post('/api/v1/permissions/check', (req: Request, res: Response) => {
    try {
      const { principal, permission, permissions } = req.body;
      if (!principal) return res.status(400).json({ error: 'principal is required' });

      if (permissions && Array.isArray(permissions)) {
        const hasAll = permissionChecker.hasAllPermissions(principal, permissions);
        const hasAny = permissionChecker.hasAnyPermission(principal, permissions);
        const effective = permissionChecker.getEffectivePermissions(principal);
        return res.json({ hasAll, hasAny, effectivePermissions: effective });
      }

      if (permission) {
        const has = permissionChecker.hasPermission(principal, permission);
        const effective = permissionChecker.getEffectivePermissions(principal);
        return res.json({ hasPermission: has, permission, effectivePermissions: effective });
      }

      return res.status(400).json({ error: 'permission or permissions array is required' });
    } catch (err) {
      logger.error({ err }, 'Permission check failed');
      return res.status(500).json({ error: 'Permission check failed' });
    }
  });

  // ============================================================================
  // ERROR HANDLER
  // ============================================================================


// ═══════════════════════════════════════════════════════════════════════════════
// 2060 SMART RESILIENCE LAYER — Auto-wired by Trancendos Compliance Engine
// ═══════════════════════════════════════════════════════════════════════════════
import {
  SmartTelemetry,
  SmartEventBus,
  SmartCircuitBreaker,
  telemetryMiddleware,
  adaptiveRateLimitMiddleware,
  createHealthEndpoint,
  setupGracefulShutdown,
} from '../middleware/resilience-layer';

// Initialize 2060 singletons
const telemetry2060 = SmartTelemetry.getInstance();
const eventBus2060 = SmartEventBus.getInstance();
const circuitBreaker2060 = new SmartCircuitBreaker(`${SERVICE_ID}-primary`, {
  failureThreshold: 5,
  resetTimeoutMs: 30000,
  halfOpenMaxAttempts: 3,
});

// Wire telemetry middleware (request tracking + trace propagation)
app.use(telemetryMiddleware);

// Wire adaptive rate limiting (IAM-level aware)
app.use(adaptiveRateLimitMiddleware);

// 2060 Enhanced health endpoint with resilience status
app.get('/health/2060', createHealthEndpoint({
  serviceName: SERVICE_ID,
  meshAddress: MESH_ADDRESS,
  getCustomHealth: () => ({
    circuitBreaker: circuitBreaker2060.getState(),
    eventBusListeners: eventBus2060.listenerCount(),
    telemetryMetrics: telemetry2060.getMetricNames().length,
  }),
}));

// Prometheus text format metrics export
app.get('/metrics/prometheus', (_req: any, res: any) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(telemetry2060.exportPrometheus());
});

// Emit service lifecycle events
eventBus2060.emit('service.2060.wired', {
  serviceId: SERVICE_ID,
  meshAddress: MESH_ADDRESS,
  timestamp: new Date().toISOString(),
  features: ['telemetry', 'rate-limiting', 'circuit-breaker', 'event-bus', 'prometheus-export'],
});

// ═══════════════════════════════════════════════════════════════════════════════
// END 2060 SMART RESILIENCE LAYER

  // ════════════════════════════════════════════════════════════════════════════════
  // SENTINEL STATION — PQC TUNNEL ROUTES (PBV-160)
  // ════════════════════════════════════════════════════════════════════════════════
  
  const tunnelApi = Router();
  
  // POST /api/v1/tunnels — Request new tunnel
  tunnelApi.post('/', async (req: Request, res: Response) => {
    try {
      const { TunnelManager } = await import('../tunnels/tunnel-manager');
      const manager = new TunnelManager();
      
      const { sourceLocation, targetLocation, requestedClass, requestedDuration, purpose, requestedBy, context } = req.body;
      
      if (!sourceLocation || !targetLocation || !purpose || !requestedBy) {
        return res.status(400).json({ error: 'Missing required fields', required: ['sourceLocation', 'targetLocation', 'purpose', 'requestedBy'] });
      }
      
      const decision = await manager.requestTunnel({
        requestId: `tr-${Date.now()}`,
        sourceLocation, targetLocation,
        requestedClass: requestedClass || 'beta',
        requestedDuration: requestedDuration || 3600,
        purpose, requestedBy,
        context: context || { securityClearance: 'internal', dataClassification: 'internal', urgency: 'medium', complianceRequirements: [] }
      });
      
      logger.info('Tunnel requested', { requestId: decision.requestId, approved: decision.approved });
      return res.status(decision.approved ? 201 : 403).json(decision);
    } catch (error) {
      logger.error('Tunnel request error', { error });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  // GET /api/v1/tunnels — List tunnels
  tunnelApi.get('/', async (req: Request, res: Response) => {
    try {
      const { TunnelManager } = await import('../tunnels/tunnel-manager');
      const manager = new TunnelManager();
      const state = req.query.state as string;
      const tunnels = manager.listTunnels(state as any);
      return res.json({ count: tunnels.length, tunnels: tunnels.map(t => ({ id: t.id, name: t.name, state: t.state, source: t.sourceLocation, target: t.targetLocation })) });
    } catch (error) {
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  // GET /api/v1/tunnels/:id — Get tunnel details
  tunnelApi.get('/:id', async (req: Request, res: Response) => {
    try {
      const { TunnelManager } = await import('../tunnels/tunnel-manager');
      const manager = new TunnelManager();
      const tunnel = manager.getTunnel(req.params.id);
      if (!tunnel) return res.status(404).json({ error: 'Tunnel not found' });
      return res.json(tunnel);
    } catch (error) {
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  // POST /api/v1/tunnels/:id/activate — Activate tunnel
  tunnelApi.post('/:id/activate', async (req: Request, res: Response) => {
    try {
      const { TunnelManager } = await import('../tunnels/tunnel-manager');
      const manager = new TunnelManager();
      const { sessionToken } = req.body;
      if (!sessionToken) return res.status(400).json({ error: 'sessionToken required' });
      const tunnel = await manager.activateTunnel(req.params.id, sessionToken);
      logger.info('Tunnel activated', { tunnelId: tunnel.id });
      return res.json(tunnel);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return res.status(400).json({ error: msg });
    }
  });
  
  // DELETE /api/v1/tunnels/:id — Terminate tunnel
  tunnelApi.delete('/:id', async (req: Request, res: Response) => {
    try {
      const { TunnelManager } = await import('../tunnels/tunnel-manager');
      const manager = new TunnelManager();
      const tunnel = await manager.terminateTunnel(req.params.id, req.query.reason as string || 'Manual termination');
      logger.info('Tunnel terminated', { tunnelId: tunnel.id });
      return res.json(tunnel);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return res.status(400).json({ error: msg });
    }
  });
  
  app.use('/api/v1/tunnels', tunnelApi);
  logger.info('Sentinel Station tunnel routes mounted at /api/v1/tunnels');
// ═══════════════════════════════════════════════════════════════════════════════

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err }, 'Unhandled error');
    res.status(500).json({ error: 'Internal server error', message: err.message });
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  return app;
}