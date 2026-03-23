/**
 * Sentinel Station — Tunnel Manager Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { TunnelManager } from '../tunnel-manager';
import { TunnelRequest, TunnelState, SlipstreamClass } from '../tunnel-types';

describe('TunnelManager', () => {
  let manager: TunnelManager;

  beforeEach(() => {
    manager = new TunnelManager();
  });

  const createTestRequest = (overrides: Partial<TunnelRequest> = {}): TunnelRequest => ({
    requestId: 'test-request-1',
    sourceLocation: 'the-citadel',
    targetLocation: 'the-void',
    requestedClass: 'beta',
    requestedDuration: 3600,
    purpose: 'Test tunnel for data transfer',
    requestedBy: 'test-agent',
    context: {
      securityClearance: 'internal',
      dataClassification: 'internal',
      urgency: 'medium',
      complianceRequirements: []
    },
    ...overrides
  });

  describe('requestTunnel', () => {
    it('should create a dormant tunnel', async () => {
      const request = createTestRequest();
      const decision = await manager.requestTunnel(request);

      expect(decision.approved).toBe(true);
      expect(decision.tunnel).toBeDefined();
      expect(decision.tunnel?.state).toBe('dormant');
      expect(decision.tunnel?.sourceLocation).toBe('the-citadel');
      expect(decision.tunnel?.targetLocation).toBe('the-void');
    });

    it('should classify tunnel into appropriate slipstream class', async () => {
      const request = createTestRequest({ requestedClass: 'alpha' });
      const decision = await manager.requestTunnel(request);

      expect(decision.tunnel?.slipstreamClass).toBe('alpha');
    });

    it('should generate PQC key pair', async () => {
      const request = createTestRequest();
      const decision = await manager.requestTunnel(request);

      expect(decision.tunnel?.pqcPublicKey).toBeDefined();
      expect(decision.tunnel?.pqcPublicKey.length).toBeGreaterThan(0);
    });

    it('should set threat level based on context', async () => {
      const request = createTestRequest({
        context: {
          securityClearance: 'top-secret',
          dataClassification: 'restricted',
          urgency: 'critical',
          complianceRequirements: ['GDPR']
        }
      });
      const decision = await manager.requestTunnel(request);

      expect(decision.tunnel?.threatLevel).toBe('black');
    });
  });

  describe('activateTunnel', () => {
    it('should activate a dormant tunnel', async () => {
      const request = createTestRequest();
      const decision = await manager.requestTunnel(request);
      const tunnelId = decision.tunnel!.id;

      const activated = await manager.activateTunnel(tunnelId, 'session-token-123');

      expect(activated.state).toBe('active');
      expect(activated.activatedAt).toBeDefined();
      expect(activated.sessionToken).toBe('session-token-123');
    });

    it('should throw if tunnel not found', async () => {
      await expect(
        manager.activateTunnel('nonexistent', 'token')
      ).rejects.toThrow('Tunnel not found');
    });

    it('should throw if tunnel not dormant', async () => {
      const request = createTestRequest();
      const decision = await manager.requestTunnel(request);
      const tunnelId = decision.tunnel!.id;
      
      await manager.activateTunnel(tunnelId, 'token');

      await expect(
        manager.activateTunnel(tunnelId, 'token2')
      ).rejects.toThrow('not in dormant state');
    });
  });

  describe('listTunnels', () => {
    it('should list all tunnels', async () => {
      await manager.requestTunnel(createTestRequest({ requestId: 'r1' }));
      await manager.requestTunnel(createTestRequest({ requestId: 'r2' }));

      const tunnels = manager.listTunnels();

      expect(tunnels.length).toBe(2);
    });

    it('should filter by state', async () => {
      const decision = await manager.requestTunnel(createTestRequest());
      await manager.activateTunnel(decision.tunnel!.id, 'token');

      const activeTunnels = manager.listTunnels('active');
      const dormantTunnels = manager.listTunnels('dormant');

      expect(activeTunnels.length).toBe(1);
      expect(dormantTunnels.length).toBe(0);
    });
  });

  describe('terminateTunnel', () => {
    it('should terminate an active tunnel', async () => {
      const decision = await manager.requestTunnel(createTestRequest());
      const tunnelId = decision.tunnel!.id;
      await manager.activateTunnel(tunnelId, 'token');

      const terminated = await manager.terminateTunnel(tunnelId, 'Test termination');

      expect(terminated.state).toBe('terminated');
    });
  });

  describe('threat elevation', () => {
    it('should elevate threat level', async () => {
      const decision = await manager.requestTunnel(createTestRequest());
      const tunnelId = decision.tunnel!.id;
      await manager.activateTunnel(tunnelId, 'token');

      const elevated = await manager.elevateThreat(tunnelId, 'red', 'Suspicious activity detected');

      expect(elevated.threatLevel).toBe('red');
    });

    it('should auto-terminate on black threat', async () => {
      const decision = await manager.requestTunnel(createTestRequest());
      const tunnelId = decision.tunnel!.id;
      await manager.activateTunnel(tunnelId, 'token');

      const terminated = await manager.elevateThreat(tunnelId, 'black', 'Critical security breach');

      expect(terminated.state).toBe('terminated');
      expect(terminated.threatLevel).toBe('black');
    });
  });
});