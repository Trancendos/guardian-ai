/**
 * Guardian — Tunnel API Routes
 * 
 * REST API for Sentinel Station PQC tunnel management.
 * Extends Guardian's zero-trust engine with inter-location tunnel capabilities.
 * 
 * Endpoints:
 *   POST   /api/v1/tunnels                — Request new tunnel
 *   GET    /api/v1/tunnels                — List all tunnels
 *   GET    /api/v1/tunnels/:id            — Get tunnel details
 *   POST   /api/v1/tunnels/:id/activate   — Activate dormant tunnel
 *   POST   /api/v1/tunnels/:id/drain      — Drain tunnel (graceful shutdown)
 *   DELETE /api/v1/tunnels/:id            — Terminate tunnel
 *   POST   /api/v1/tunnels/:id/threat     — Elevate threat level
 *   GET    /api/v1/tunnels/location/:name — Tunnels for a location
 * 
 * @module api/tunnel-routes
 */

import { Router, Request, Response } from 'express';
import { tunnelManager } from '../tunnels/tunnel-manager';
import { logger } from '../utils/logger';
import type { TunnelRequest, TunnelState, ThreatLevel } from '../tunnels/tunnel-types';

export const tunnelRouter = Router();

// ============================================================================
// TUNNEL REQUEST
// ============================================================================

tunnelRouter.post('/', async (req: Request, res: Response) => {
  try {
    const {
      sourceLocation,
      targetLocation,
      requestedClass,
      requestedDuration,
      purpose,
      requestedBy,
      context
    } = req.body;

    if (!sourceLocation || !targetLocation || !purpose || !requestedBy) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['sourceLocation', 'targetLocation', 'purpose', 'requestedBy']
      });
    }

    const tunnelRequest: TunnelRequest = {
      requestId: `tr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      sourceLocation,
      targetLocation,
      requestedClass: requestedClass || 'beta',
      requestedDuration: requestedDuration || 3600,
      purpose,
      requestedBy,
      context: context || {
        securityClearance: 'internal',
        dataClassification: 'internal',
        urgency: 'medium',
        complianceRequirements: []
      }
    };

    const decision = await tunnelManager.requestTunnel(tunnelRequest);

    logger.info('Tunnel requested via API', {
      requestId: tunnelRequest.requestId,
      approved: decision.approved,
      tunnelId: decision.tunnel?.id
    });

    return res.status(decision.approved ? 201 : 403).json(decision);
  } catch (error) {
    logger.error('Tunnel request failed', { error });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// LIST TUNNELS
// ============================================================================

tunnelRouter.get('/', (req: Request, res: Response) => {
  const state = req.query.state as TunnelState | undefined;
  
  const tunnels = tunnelManager.listTunnels(state);
  
  return res.json({
    count: tunnels.length,
    tunnels: tunnels.map(t => ({
      id: t.id,
      name: t.name,
      state: t.state,
      slipstreamClass: t.slipstreamClass,
      sourceLocation: t.sourceLocation,
      targetLocation: t.targetLocation,
      threatLevel: t.threatLevel,
      createdAt: t.createdAt,
      expiresAt: t.expiresAt,
      bytesTransferred: t.bytesTransferred
    }))
  });
});

// ============================================================================
// GET TUNNEL BY ID
// ============================================================================

tunnelRouter.get('/:id', (req: Request, res: Response) => {
  const tunnel = tunnelManager.getTunnel(req.params.id);
  
  if (!tunnel) {
    return res.status(404).json({ error: 'Tunnel not found' });
  }
  
  return res.json(tunnel);
});

// ============================================================================
// ACTIVATE TUNNEL
// ============================================================================

tunnelRouter.post('/:id/activate', async (req: Request, res: Response) => {
  try {
    const { sessionToken } = req.body;
    
    if (!sessionToken) {
      return res.status(400).json({ error: 'sessionToken required' });
    }
    
    const tunnel = await tunnelManager.activateTunnel(req.params.id, sessionToken);
    
    logger.info('Tunnel activated via API', { tunnelId: tunnel.id });
    
    return res.json(tunnel);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    
    if (message.includes('not found')) {
      return res.status(404).json({ error: message });
    }
    
    return res.status(400).json({ error: message });
  }
});

// ============================================================================
// DRAIN TUNNEL
// ============================================================================

tunnelRouter.post('/:id/drain', async (req: Request, res: Response) => {
  try {
    const { reason } = req.body;
    
    const tunnel = await tunnelManager.drainTunnel(
      req.params.id, 
      reason || 'Manual drain requested'
    );
    
    logger.info('Tunnel draining via API', { tunnelId: tunnel.id, reason });
    
    return res.json(tunnel);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return res.status(400).json({ error: message });
  }
});

// ============================================================================
// TERMINATE TUNNEL
// ============================================================================

tunnelRouter.delete('/:id', async (req: Request, res: Response) => {
  try {
    const { reason } = req.query;
    
    const tunnel = await tunnelManager.terminateTunnel(
      req.params.id,
      (reason as string) || 'Manual termination'
    );
    
    logger.info('Tunnel terminated via API', { tunnelId: tunnel.id });
    
    return res.json(tunnel);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return res.status(400).json({ error: message });
  }
});

// ============================================================================
// ELEVATE THREAT LEVEL
// ============================================================================

tunnelRouter.post('/:id/threat', async (req: Request, res: Response) => {
  try {
    const { threatLevel, reason } = req.body;
    
    if (!threatLevel) {
      return res.status(400).json({ error: 'threatLevel required' });
    }
    
    const validLevels: ThreatLevel[] = ['green', 'amber', 'red', 'black'];
    if (!validLevels.includes(threatLevel)) {
      return res.status(400).json({ 
        error: 'Invalid threat level',
        validLevels 
      });
    }
    
    const tunnel = await tunnelManager.elevateThreat(
      req.params.id,
      threatLevel,
      reason || 'Threat level elevated via API'
    );
    
    logger.warn('Threat level elevated via API', { 
      tunnelId: tunnel.id, 
      threatLevel: tunnel.threatLevel 
    });
    
    return res.json(tunnel);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return res.status(400).json({ error: message });
  }
});

// ============================================================================
// TUNNELS FOR LOCATION
// ============================================================================

tunnelRouter.get('/location/:name', (req: Request, res: Response) => {
  const tunnels = tunnelManager.getTunnelsForLocation(req.params.name);
  
  return res.json({
    location: req.params.name,
    count: tunnels.length,
    tunnels
  });
});