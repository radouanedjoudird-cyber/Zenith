/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - DYNAMIC RBAC GUARD
 * ============================================================================
 * @module RolesGuard
 * @version 7.4.0
 * @description Orchestrates identity-to-role matching with support for dynamic policies.
 * * ARCHITECTURAL RATIONALE:
 * 1. DYNAMIC_RESOLVING: Matches roles against the dynamic 'role' claim in JWT.
 * 2. MULTI_TENANCY_READY: Supports tiered role validation (e.g., SUPER_ADMIN inheritance).
 * 3. FAIL_FAST_SECURITY: Immediate rejection if identity context is missing.
 * ============================================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger('ZENITH_ROLE_GUARD');

  constructor(private readonly reflector: Reflector) {}

  /**
   * @method canActivate
   * @description Validates if the authenticated principal possesses the authorized role.
   */
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    /**
     * BYPASS_STRATEGY:
     * If no @Roles() decorator is present, the guard defers authorization to PBAC/ABAC layers.
     */
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const { user, url, ip } = context.switchToHttp().getRequest();

    /**
     * IDENTITY_CONTEXT_VALIDATION:
     * High-severity check to ensure the request has passed through the Authentication layer.
     */
    if (!user || !user.role) {
      this.logger.error(`🚨 [SECURITY_BREACH] Unauthorized role-check attempt on ${url} from IP: ${ip}`);
      throw new ForbiddenException('ZENITH_SHIELD: Identity context missing or role unassigned.');
    }

    /**
     * RBAC_MATCH_ENGINE:
     * Checks if the user's role (string from JWT) is included in the authorized role set.
     * Special Logic: SUPER_ADMIN bypasses granular role restrictions.
     */
    const hasAuthorizedRole = requiredRoles.some((role) => {
      return user.role === role || user.role === Role.SUPER_ADMIN;
    });

    if (!hasAuthorizedRole) {
      this.logger.warn(
        `⚠️ [ACCESS_DENIED] Identity ${user.email} (Role: ${user.role}) attempted to access ${url}`
      );
      throw new ForbiddenException('ZENITH_SHIELD: Insufficient administrative clearance.');
    }

    return true;
  }
}