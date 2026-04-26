/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - ENTERPRISE RBAC & ACCESS CONTROL GUARD
 * ============================================================================
 * @module RolesGuard
 * @version 7.4.0
 * @author Zenith Systems Engine
 * @description Centralized Authorization Engine implementing NIST-compliant RBAC.
 * * * ARCHITECTURAL COMPLIANCE:
 * 1. PRIVILEGE_INHERITANCE: Automatic escalation for SUPER_ADMIN principals.
 * 2. AUDIT_TRAIL: Comprehensive logging of authorization decisions and breaches.
 * 3. TYPE_SAFETY: Strict Enum-based role validation.
 * 4. FAIL_SAFE_MECHANISM: Rejects by default if context is ambiguous.
 * ============================================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger('ZENITH_SECURITY_SHIELD');

  constructor(private readonly reflector: Reflector) {}

  /**
   * @method canActivate
   * @description Core authorization logic to intercept and validate principal roles.
   * @param context Execution context containing request and metadata.
   * @returns boolean | Promise<boolean>
   * @throws ForbiddenException If access criteria are not met.
   */
  canActivate(context: ExecutionContext): boolean {
    // 1. EXTRACT_METADATA: Retrieve required roles from decorators (handler or class level)
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // 2. DEFAULT_PASS_STRATEGY: If no @Roles() is defined, allow access (Open-by-default for non-gated routes)
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // 3. EXTRACT_HTTP_CONTEXT: Destructure essential telemetry from the request object
    const request = context.switchToHttp().getRequest();
    const { user, url, method, ip } = request;

    // 4. IDENTITY_VERIFICATION: Ensure request has been processed by AtGuard (Auth layer)
    if (!user) {
      this.logger.error(
        `🚨 [SECURITY_BREACH] Unauthorized access attempt on [${method}] ${url} from IP: ${ip}`
      );
      throw new UnauthorizedException('ZENITH_SHIELD: Authentication context not found.');
    }

    /**
     * 5. HIERARCHICAL_AUTHORIZATION_ENGINE:
     * Logic:
     * a) Check if user holds the SUPER_ADMIN 'Master Key'.
     * b) If not, check if user's role matches any in the requiredRoles set.
     */
    const isSuperAdmin = user.role === Role.SUPER_ADMIN;
    const hasRoleMatch = requiredRoles.includes(user.role);

    // MASTER_KEY_BYPASS: SuperAdmin bypasses all granular role checks
    if (isSuperAdmin) {
      this.logger.log(`🔑 [PRIVILEGE_BYPASS] SuperAdmin access granted for ${user.email} on ${url}`);
      return true;
    }

    // ROLE_VALIDATION: Standard RBAC check
    if (!hasRoleMatch) {
      this.logger.warn(
        `⚠️ [ACCESS_DENIED] Identity: ${user.email} | Role: ${user.role} | Target: ${url} | IP: ${ip}`
      );
      
      throw new ForbiddenException({
        success: false,
        statusCode: 403,
        error: 'SECURITY_BREACH_DETECTED',
        message: 'ZENITH_SHIELD: Insufficient administrative clearance.',
        traceId: request.headers['x-trace-id'] || 'INTERNAL_TRACE',
      });
    }

    // 6. FINAL_AUTHORIZATION: Access validated
    return true;
  }
}