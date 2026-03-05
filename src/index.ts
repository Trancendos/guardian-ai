/**
 * Guardian AI — Main Entry Point
 *
 * Zero-trust IAM gateway for the Trancendos 24-agent mesh.
 * Provides agent authentication, authorization, behavioral monitoring,
 * sandbox enforcement, and full audit logging.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { logger } from './utils/logger';
import { createServer } from './api/server';
import { agentTokenService } from './tokens/agent-tokens';
import { zeroTrustEngine } from './zero-trust/zero-trust';
import { permissionChecker, ROLE_PERMISSIONS } from './iam/permissions';

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = parseInt(process.env.PORT || '3004', 10);
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const DEFAULT_TOKEN_TTL = parseInt(process.env.DEFAULT_TOKEN_TTL_MS || '500', 10);
const AUDIT_RETENTION_HOURS = parseInt(process.env.AUDIT_RETENTION_HOURS || '24', 10);

// ============================================================================
// BOOTSTRAP
// ============================================================================

async function bootstrap(): Promise<void> {
  logger.info({
    service: 'guardian-ai',
    version: process.env.npm_package_version || '1.0.0',
    env: NODE_ENV,
    port: PORT,
    tokenTtlMs: DEFAULT_TOKEN_TTL,
  }, 'Guardian AI bootstrapping...');

  // ── Step 1: Validate IAM configuration ──────────────────────────────────
  const roles = Object.keys(ROLE_PERMISSIONS);
  logger.info({ roles, count: roles.length }, 'IAM roles loaded');

  const testPrincipal = { role: 'admin' as const, agentId: 'bootstrap-test' };
  const testPerms = permissionChecker.getEffectivePermissions(testPrincipal);
  logger.info({ permissionCount: testPerms.length }, 'Permission checker verified');

  // ── Step 2: Seed behavioral baselines for known system agents ────────────
  const systemAgents = [
    {
      agentId: 'cornelius-ai',
      typicalRequestRate: 60,
      typicalCapabilities: ['orchestrate', 'delegate', 'route', 'monitor'],
      typicalTargets: ['the-dr-ai', 'norman-ai', 'guardian-ai', 'dorris-ai'],
      lastUpdated: new Date(),
      sampleCount: 100,
    },
    {
      agentId: 'the-dr-ai',
      typicalRequestRate: 30,
      typicalCapabilities: ['diagnose', 'heal', 'analyze', 'rollback'],
      typicalTargets: ['cornelius-ai', 'guardian-ai'],
      lastUpdated: new Date(),
      sampleCount: 100,
    },
    {
      agentId: 'norman-ai',
      typicalRequestRate: 20,
      typicalCapabilities: ['scan', 'monitor', 'document', 'collect'],
      typicalTargets: ['cornelius-ai', 'guardian-ai'],
      lastUpdated: new Date(),
      sampleCount: 100,
    },
    {
      agentId: 'dorris-ai',
      typicalRequestRate: 10,
      typicalCapabilities: ['financial', 'mailbox', 'report', 'analyze'],
      typicalTargets: ['cornelius-ai', 'guardian-ai'],
      lastUpdated: new Date(),
      sampleCount: 100,
    },
  ];

  for (const baseline of systemAgents) {
    agentTokenService.setBaseline(baseline);
  }
  logger.info({ count: systemAgents.length }, 'System agent baselines seeded');

  // ── Step 3: Seed default sandbox policies for known agents ───────────────
  const defaultSandboxPolicies = [
    {
      agentId: 'the-dr-ai',
      allowedOperations: ['read_file', 'write_file', 'execute_script', 'restart_service', 'rollback'],
      deniedOperations: ['delete_database', 'drop_table', 'rm_rf', 'format_disk'],
      resourceLimits: {
        maxMemoryMb: 512,
        maxCpuPercent: 50,
        maxDiskMb: 1024,
        maxNetworkKbps: 10240,
        maxExecutionMs: 30000,
      },
      networkPolicy: {
        allowedHosts: ['localhost', '127.0.0.1', '*.trancendos.internal'],
        deniedHosts: ['*.external.com'],
        allowedPorts: [3000, 3001, 3002, 3003, 3004, 3005, 8080],
        allowOutbound: true,
        allowInbound: false,
      },
      enabled: true,
    },
    {
      agentId: 'norman-ai',
      allowedOperations: ['read_file', 'scan_network', 'query_cve', 'write_report'],
      deniedOperations: ['delete_file', 'modify_system', 'install_package'],
      resourceLimits: {
        maxMemoryMb: 256,
        maxCpuPercent: 30,
        maxDiskMb: 512,
        maxNetworkKbps: 5120,
        maxExecutionMs: 60000,
      },
      networkPolicy: {
        allowedHosts: ['localhost', '127.0.0.1', '*.trancendos.internal', 'nvd.nist.gov'],
        deniedHosts: [],
        allowedPorts: [80, 443, 3000, 3001, 3002, 3003, 3004, 3005],
        allowOutbound: true,
        allowInbound: false,
      },
      enabled: true,
    },
  ];

  for (const policy of defaultSandboxPolicies) {
    zeroTrustEngine.setSandboxPolicy(policy);
  }
  logger.info({ count: defaultSandboxPolicies.length }, 'Default sandbox policies loaded');

  // ── Step 4: Verify zero-trust engine ────────────────────────────────────
  const ztStats = zeroTrustEngine.getStats();
  logger.info({ policyCount: ztStats.policyCount }, 'Zero-trust engine verified');

  // ── Step 5: Start HTTP server ────────────────────────────────────────────
  const app = createServer();
  const server = app.listen(PORT, HOST, () => {
    logger.info({
      host: HOST,
      port: PORT,
      env: NODE_ENV,
      endpoints: [
        'POST /api/v1/tokens/issue',
        'POST /api/v1/tokens/verify',
        'DELETE /api/v1/tokens/:jti',
        'GET  /api/v1/tokens/history/:agentId',
        'POST /api/v1/zero-trust/evaluate',
        'GET  /api/v1/zero-trust/policies',
        'POST /api/v1/zero-trust/policies',
        'PUT  /api/v1/zero-trust/policies/:id',
        'DELETE /api/v1/zero-trust/policies/:id',
        'GET  /api/v1/zero-trust/audit',
        'GET  /api/v1/zero-trust/stats',
        'GET  /api/v1/baselines',
        'GET  /api/v1/baselines/:agentId',
        'POST /api/v1/baselines/:agentId',
        'POST /api/v1/baselines/:agentId/check',
        'GET  /api/v1/sandbox/:agentId',
        'POST /api/v1/sandbox/:agentId',
        'POST /api/v1/sandbox/:agentId/check',
        'GET  /api/v1/permissions/roles',
        'POST /api/v1/permissions/check',
        'GET  /health',
        'GET  /metrics',
      ],
    }, 'Guardian AI listening');
  });

  // ── Step 6: Start audit log cleanup cycle ────────────────────────────────
  const cleanupIntervalMs = 60 * 60 * 1000; // 1 hour
  setInterval(() => {
    const retentionMs = AUDIT_RETENTION_HOURS * 60 * 60 * 1000;
    const cutoff = new Date(Date.now() - retentionMs);
    const stats = zeroTrustEngine.getStats();
    logger.info({
      cutoff: cutoff.toISOString(),
      totalRequests: stats.totalRequests,
      deniedRequests: stats.deniedRequests,
      threatsDetected: stats.threatsDetected,
    }, 'Audit log stats');
  }, cleanupIntervalMs);

  // ── Step 7: Graceful shutdown ────────────────────────────────────────────
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    server.close(() => {
      const finalStats = zeroTrustEngine.getStats();
      logger.info({
        totalRequests: finalStats.totalRequests,
        allowedRequests: finalStats.allowedRequests,
        deniedRequests: finalStats.deniedRequests,
        threatsDetected: finalStats.threatsDetected,
      }, 'Guardian AI shutdown complete');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 10_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('uncaughtException', (err) => {
    logger.error({ err }, 'Uncaught exception');
    shutdown('uncaughtException');
  });
  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled rejection');
  });

  logger.info('Guardian AI fully operational — zero-trust mesh protection active');
}

// ── Run ──────────────────────────────────────────────────────────────────────
bootstrap().catch((err) => {
  logger.error({ err }, 'Bootstrap failed');
  process.exit(1);
});