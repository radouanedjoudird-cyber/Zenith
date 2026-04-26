/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - AUTHORIZATION METADATA DECORATOR
 * ============================================================================
 * @module RolesDecorator
 * @version 7.4.0
 * @author Zenith Systems Engine
 * @description Injects authorization metadata for Role-Based Access Control (RBAC).
 * * * ARCHITECTURAL RATIONALE:
 * 1. METADATA_REFLECTION: Enables the RolesGuard to inspect required privileges at runtime.
 * 2. SCHEMA_VALIDATION: Enforces the use of the centralized 'Role' Enum.
 * 3. SECURITY_DECLARATION: Provides an explicit, readable way to gate API resources.
 * ============================================================================
 */

import { CustomDecorator, SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

/**
 * @constant ROLES_KEY
 * @type {string}
 * @description The unique identifier for role-based metadata storage in the reflection context.
 */
export const ROLES_KEY = 'roles';

/**
 * @decorator Roles
 * @description
 * Annotates a controller or specific handler to restrict access based on user identity.
 * This decorator is the primary entry point for Zenith's RBAC subsystem.
 * * * SECURITY PROTOCOL:
 * - If multiple roles are provided, the principal must possess AT LEAST one.
 * - Integration: Intercepted by 'RolesGuard' for identity-to-claim matching.
 * * * @example
 * // Restricted to System Administrators and Infrastructure SuperAdmins
 * @Roles(Role.ADMIN, Role.SUPER_ADMIN)
 * @Get('system/audit')
 * * * @param {Role[]} roles - A spread of authorized identities from the Role Enum.
 * @returns {CustomDecorator<string>} Metadata-bound decorator.
 */
export const Roles = (...roles: Role[]): CustomDecorator<string> => 
  SetMetadata(ROLES_KEY, roles);