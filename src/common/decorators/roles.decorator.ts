/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - IDENTITY HIERARCHY METADATA
 * ============================================================================
 * @module RolesDecorator
 * @version 7.4.0
 * @description Injects authorization metadata for Role-Based Access Control (RBAC).
 * * ARCHITECTURAL RATIONALE:
 * 1. HIERARCHICAL_ACCESS: Tags routes with required identity levels (e.g., ADMIN).
 * 2. TYPE_SAFETY: Leverages the 'Role' constant/type for compiler-level validation.
 * 3. COMPATIBILITY: Works in tandem with RolesGuard for dynamic claim verification.
 * ============================================================================
 */

import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

/**
 * @constant ROLES_KEY
 * @description Unique metadata key used by the RolesGuard for identity reflection.
 */
export const ROLES_KEY = 'roles';

/**
 * @decorator Roles
 * @description
 * Restricts route access to specific identity groups defined in the system. 
 * Essential for macro-level authorization before granular PBAC checks.
 * * * SECURITY STRATEGY:
 * Implements a "Guard Rail" approach where only users with the matching 
 * role claim in their JWT can enter the execution context.
 * * @example
 * @Roles(Role.ADMIN, Role.SUPER_ADMIN)
 * @Delete('kernel/purge')
 * * @param roles - A spread of authorized Role constants.
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);