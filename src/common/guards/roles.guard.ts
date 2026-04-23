/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - ROLE-BASED ACCESS CONTROL (RBAC) GUARD
 * ============================================================================
 * @description Validates user privileges based on the @Roles() decorator.
 */

import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  /**
   * @method canActivate
   * @description Orchestrates the identity-to-role matching logic.
   */
  canActivate(context: ExecutionContext): boolean {
    // 1. Identify if the current route has specific role requirements
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // 2. If no roles are defined via @Roles(), the gate is open by default
    if (!requiredRoles) {
      return true;
    }

    // 3. Extract the user object (injected by AtGuard) from the request
    const { user } = context.switchToHttp().getRequest();

    /**
     * @logic MATCH_VALIDATION
     * Validates if the principal's role is contained within the authorized set.
     */
    return requiredRoles.some((role) => user?.role === role);
  }
}