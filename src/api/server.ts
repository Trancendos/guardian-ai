/**
 * Guardian — REST API Server
 *
 * Exposes Guardian's IAM, zero-trust, token, and sandbox capabilities
 * as a REST API for the Trancendos agent mesh.
 *
 * Endpoints:
 *   POST   /api/v1/tokens/issue           — Issue agent token
 *   POST   /api/v1/tokens/verify          — Verify agent token
 *   DELETE /api/v1/tokens/:jti            — Revoke token
 *   GET    /api/v1/tokens/history/:agentId — Token history
 *
 *   POST   /api/v1/zero-trust/evaluate    — Evaluate zero-trust request
 *   GET    /api/v1/zero-trust/policies    — List policies
 *   POST   /api/v1/zero-trust/policies    — Create policy
 *   PUT    /api/v1/zero-trust/policies/:id — Update policy
 *   DELETE /api/v1/zero-trust/policies/:id — Delete policy
 *   GET    /api/v1/zero-trust/audit       — Audit log
 *   GET    /api/v1/zero-trust/stats       — Stats
 *
 *   GET    /api/v1/baselines              — All behavioral baselines
 *   GET    /api/v1/baselines/:agentId     — Agent baseline
 *   POST   /api/v1/baselines/:agentId     — Set baseline
 *
 *   GET    /api/v1/sandbox/:agentId       — Get sandbox policy
 *   POST   /api/v1/sandbox/:agentId       — Set sandbox policy
 *   POST   /api/v1/sandbox/:agentId/check — Check sandbox operation
 *
 *   GET    /api/v1/permissions/roles      — List roles + permissions
 *   POST   /api/v1/permissions/check      — Check permission
 *
 *   GET    /health                        — Health check
 *   GET    /metrics                       — Service metrics
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { agentTokenService } from '../tokens/agent-tokens';
import { zeroTrustEngine } from '../zero-trust/zero-trust';
import { permissionChecker, ROLE_PERMISSIONS, AgentPermission } from '../iam/permissions';
import type { ZeroTrustRequest } from '../zero-trust/zero-trust';
import type { UserRole } from '../iam/permissions';

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
      service: 'guardian-ai',
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      policies: stats.policyCount,
      baselines: agentTokenService.getAllBaselines().length,
      revokedTokens: agentTokenService.getRevokedCount(),
    });
  });

  app.get('/metrics', (_req: Request, res: Response) => {
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

  // DELETE /api/v1/tokens/:jti
  app.delete('/api/v1/tokens/:jti', (req: Request, res: Response) => {
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

  // GET /api/v1/tokens/history/:agentId
  app.get('/api/v1/tokens/history/:agentId', (req: Request, res: Response) => {
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

  // GET /api/v1/zero-trust/policies
  app.get('/api/v1/zero-trust/policies', (_req: Request, res: Response) => {
    const policies = zeroTrustEngine.getPolicies();
    return res.json({ count: policies.length, policies });
  });

  // POST /api/v1/zero-trust/policies
  app.post('/api/v1/zero-trust/policies', (req: Request, res: Response) => {
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

  // PUT /api/v1/zero-trust/policies/:id
  app.put('/api/v1/zero-trust/policies/:id', (req: Request, res: Response) => {
    try {
      const updated = zeroTrustEngine.updatePolicy(req.params.id, req.body);
      if (!updated) return res.status(404).json({ error: 'Policy not found' });
      return res.json(updated);
    } catch (err) {
      logger.error({ err }, 'Policy update failed');
      return res.status(500).json({ error: 'Policy update failed' });
    }
  });

  // DELETE /api/v1/zero-trust/policies/:id
  app.delete('/api/v1/zero-trust/policies/:id', (req: Request, res: Response) => {
    const deleted = zeroTrustEngine.deletePolicy(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Policy not found' });
    return res.json({ deleted: true, id: req.params.id });
  });

  // GET /api/v1/zero-trust/audit
  app.get('/api/v1/zero-trust/audit', (req: Request, res: Response) => {
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

  // POST /api/v1/baselines/:agentId
  app.post('/api/v1/baselines/:agentId', (req: Request, res: Response) => {
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

  // POST /api/v1/sandbox/:agentId
  app.post('/api/v1/sandbox/:agentId', (req: Request, res: Response) => {
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

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err }, 'Unhandled error');
    res.status(500).json({ error: 'Internal server error', message: err.message });
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  return app;
}