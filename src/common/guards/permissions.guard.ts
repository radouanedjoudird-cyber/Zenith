import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

/**
 * ZENITH PERMISSIONS GUARD - PBAC ENGINE v2.8
 * -------------------------------------------
 * MISSION: Standardize granular access control across the Zenith infrastructure.
 * STRATEGY: Permission-Based Access Control (PBAC).
 * * ARCHITECTURE PRINCIPLES:
 * 1. ZERO-DB POLICY: Validates permissions directly from the hydrated JWT context for ultra-fast RTT.
 * 2. HIERARCHICAL RESOLUTION: Intelligently merges permissions from both Handlers and Controllers.
 * 3. FORENSIC AUDITING: Real-time logging of access violations for security monitoring.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('Zenith-Security-Guard');

  constructor(private reflector: Reflector) {}

  /**
   * EXECUTION GATEKEEPING
   * ---------------------
   * Determines if the request is authorized to proceed based on cryptographic PBAC claims.
   */
  canActivate(context: ExecutionContext): boolean {
    /**
     * REFLECTION LAYER:
     * Extracts required permissions using 'getAllAndOverride' to ensure that
     * method-level security definitions strictly take precedence over class-level ones.
     */
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>('permissions', [
      context.getHandler(),
      context.getClass(),
    ]);

    // BYPASS PROTOCOL: If no explicit permissions are defined, the path is considered 'Inherited Access'.
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    // EXTRACTION: Capturing identity and network metadata for the audit trail.
    const request = context.switchToHttp().getRequest();
    const { user, ip, method, url } = request;

    /**
     * SECURITY SHIELD: IDENTITY INTEGRITY CHECK
     * Critical failure if the user context was not hydrated by the preceding AuthGuard.
     */
    if (!user || !user.permissions) {
      this.logger.error(
        `🚨 [SECURITY_BREACH] Unauthorized access attempt to ${url} from IP: ${ip}. Identity context is NULL.`
      );
      throw new ForbiddenException('Zenith Shield: Identity context missing or corrupted.');
    }

    /**
     * CRYPTOGRAPHIC PBAC VALIDATION:
     * Logic: Implements 'All-Or-Nothing' validation for required permission sets.
     */
    const hasPermission = requiredPermissions.every((perm) =>
      user.permissions.includes(perm),
    );

    if (!hasPermission) {
      /**
       * AUDIT LOGGING:
       * Captures the specific failed permission to assist in security auditing and troubleshooting.
       */
      this.logger.warn(
        `⚠️ [ACCESS_DENIED] User: ${user.email} | Required: [${requiredPermissions}] | Origin: ${ip} | Path: ${method} ${url}`
      );
      
      throw new ForbiddenException('Zenith Shield: Insufficient granular permissions for this operation.');
    }

    // SUCCESS: Permission verified. Releasing request to the service layer.
    return true;
  }
}