/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - ACCESS CONTROL METADATA
 * ============================================================================
 * @module PermissionsDecorator
 * @version 7.4.0
 * @description Injects authorization metadata for Permission-Based Access Control (PBAC).
 * * ARCHITECTURAL RATIONALE:
 * 1. DECOUPLING: Separates routing logic from authorization policies.
 * 2. GRANULARITY: Enables fine-grained control over individual system actions.
 * 3. METADATA_INJECTION: Utilizes NestJS Reflector API for runtime policy discovery.
 * ============================================================================
 */

import { SetMetadata } from '@nestjs/common';

/**
 * @constant PERMISSIONS_KEY
 * @description Unique registry key for the Security Guard's metadata extraction.
 */
export const PERMISSIONS_KEY = 'permissions';

/**
 * @decorator Permissions
 * @description
 * Enforces strict Permission-Based Access Control (PBAC) by tagging route handlers 
 * with required system actions. This is the primary gatekeeper for v7.4.0 architecture.
 * * * SECURITY STRATEGY: 
 * Shifts authorization from "Role-level" to "Action-level" (e.g., 'IDENTITY_PURGE').
 * * @example
 * @Permissions('USER_CREATE', 'AUDIT_LOG_VIEW')
 * @Post('provision')
 * * @param permissions - A spread of strings representing authorized system actions.
 */
export const Permissions = (...permissions: string[]) => 
  SetMetadata(PERMISSIONS_KEY, permissions);