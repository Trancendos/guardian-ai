/**
 * Guardian — IAM Permissions & RBAC
 *
 * Role-based access control for the Trancendos agent mesh.
 * Controls who can create, modify, delegate to, and view agents.
 *
 * Migrated from: server/services/agentAuth.ts
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 * Component: Infinity-One (guardian-ai) — IAM & Zero-Trust
 */

import { logger } from '../utils/logger';

// ============================================================================
// PERMISSIONS & ROLES
// ============================================================================

export enum AgentPermission {
  // Agent Management
  CREATE_AGENT = 'create_agent',
  MODIFY_AGENT = 'modify_agent',
  DELETE_AGENT = 'delete_agent',
  VIEW_AGENT = 'view_agent',

  // Task Management
  DELEGATE_TASK = 'delegate_task',
  VIEW_TASK = 'view_task',
  CANCEL_TASK = 'cancel_task',

  // Communication
  SEND_MESSAGE = 'send_message',
  VIEW_CONVERSATION = 'view_conversation',

  // Configuration
  MODIFY_PERMISSIONS = 'modify_permissions',
  MODIFY_LIMITS = 'modify_limits',

  // Sensitive Operations
  VIEW_LOGS = 'view_logs',
  ROLLBACK = 'rollback',
  EXECUTE_SANDBOX = 'execute_sandbox',

  // Platform Admin
  MANAGE_USERS = 'manage_users',
  VIEW_AUDIT_LOG = 'view_audit_log',
  MANAGE_SECRETS = 'manage_secrets',
}

export type UserRole = 'owner' | 'admin' | 'user' | 'guest' | 'agent';

export const ROLE_PERMISSIONS: Record<UserRole, AgentPermission[]> = {
  owner: Object.values(AgentPermission), // Full access

  admin: [
    AgentPermission.MODIFY_AGENT,
    AgentPermission.VIEW_AGENT,
    AgentPermission.DELEGATE_TASK,
    AgentPermission.VIEW_TASK,
    AgentPermission.CANCEL_TASK,
    AgentPermission.SEND_MESSAGE,
    AgentPermission.VIEW_CONVERSATION,
    AgentPermission.VIEW_LOGS,
    AgentPermission.ROLLBACK,
    AgentPermission.VIEW_AUDIT_LOG,
    AgentPermission.MANAGE_USERS,
  ],

  user: [
    AgentPermission.VIEW_AGENT,
    AgentPermission.DELEGATE_TASK,
    AgentPermission.VIEW_TASK,
    AgentPermission.SEND_MESSAGE,
    AgentPermission.VIEW_CONVERSATION,
  ],

  guest: [
    AgentPermission.VIEW_AGENT,
    AgentPermission.VIEW_TASK,
  ],

  agent: [
    AgentPermission.VIEW_AGENT,
    AgentPermission.DELEGATE_TASK,
    AgentPermission.SEND_MESSAGE,
    AgentPermission.VIEW_CONVERSATION,
    AgentPermission.EXECUTE_SANDBOX,
  ],
};

// ============================================================================
// PERMISSION CHECKER
// ============================================================================

export interface Principal {
  id: string;
  role: UserRole;
  customPermissions?: AgentPermission[];
  deniedPermissions?: AgentPermission[];
}

export class PermissionChecker {
  /**
   * Check if a principal has a specific permission
   */
  hasPermission(principal: Principal, permission: AgentPermission): boolean {
    // Check explicit denials first
    if (principal.deniedPermissions?.includes(permission)) {
      return false;
    }

    // Check custom permissions
    if (principal.customPermissions?.includes(permission)) {
      return true;
    }

    // Check role-based permissions
    const rolePerms = ROLE_PERMISSIONS[principal.role] || [];
    return rolePerms.includes(permission);
  }

  /**
   * Check multiple permissions (all must pass)
   */
  hasAllPermissions(principal: Principal, permissions: AgentPermission[]): boolean {
    return permissions.every(p => this.hasPermission(principal, p));
  }

  /**
   * Check multiple permissions (any must pass)
   */
  hasAnyPermission(principal: Principal, permissions: AgentPermission[]): boolean {
    return permissions.some(p => this.hasPermission(principal, p));
  }

  /**
   * Get all effective permissions for a principal
   */
  getEffectivePermissions(principal: Principal): AgentPermission[] {
    const rolePerms = new Set(ROLE_PERMISSIONS[principal.role] || []);

    // Add custom permissions
    for (const p of principal.customPermissions || []) {
      rolePerms.add(p);
    }

    // Remove denied permissions
    for (const p of principal.deniedPermissions || []) {
      rolePerms.delete(p);
    }

    return Array.from(rolePerms);
  }

  /**
   * Assert permission — throws if not authorized
   */
  assertPermission(principal: Principal, permission: AgentPermission): void {
    if (!this.hasPermission(principal, permission)) {
      logger.warn(`[Guardian] Permission denied: ${principal.id} (${principal.role}) -> ${permission}`);
      throw new Error(`Permission denied: ${permission} required`);
    }
  }
}

export const permissionChecker = new PermissionChecker();