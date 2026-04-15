import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { LogStatus, Severity } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

/**
 * ZENITH ADVANCED PERMISSIONS GUARD - PBAC ENGINE v5.0
 * -----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine (Enterprise Edition)
 * STRATEGY: Permission-Based Access Control (PBAC) with Forensic Persistence.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('ZENITH_SECURITY_GUARD');

  constructor(
    private reflector: Reflector,
    private prisma: PrismaService, // Injecting Prisma for Forensic Logging
  ) {}

  /**
   * EXECUTION GATEKEEPING
   * ---------------------
   * Validates cryptographic PBAC claims and records violations.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // BYPASS: Inherited Access if no permissions are defined.
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const { user, ip, method, url } = request;
    const userAgent = request.get('user-agent') || 'Unknown Device';

    /**
     * SECURITY SHIELD: IDENTITY INTEGRITY
     */
    if (!user || !user.permissions) {
      this.logger.error(`🚨 [SECURITY_BREACH] Identity context NULL for ${url} | Origin: ${ip}`);
      throw new ForbiddenException('Zenith Shield: Identity context corrupted.');
    }

    /**
     * PBAC VALIDATION: All-Or-Nothing Strategy
     */
    const hasPermission = requiredPermissions.every((perm) =>
      user.permissions.includes(perm),
    );

    if (!hasPermission) {
      // 🛡️ TRIGGER FORENSIC ENGINE: Persistent Audit Logging
      await this.handleSecurityViolation(user, method, url, ip, userAgent, requiredPermissions);
      
      throw new ForbiddenException('Zenith Shield: Insufficient granular permissions.');
    }

    return true;
  }

  /**
   * SECURITY VIOLATION PERSISTENCE (SOC VISIBILITY)
   * ----------------------------------------------
   * Compliant with Advanced Forensic Schema v5.0
   */
  private async handleSecurityViolation(
    user: any, 
    method: string, 
    url: string, 
    ip: string, 
    userAgent: string, 
    required: string[]
  ) {
    this.logger.warn(`⚠️ [ACCESS_DENIED] Identity ${user.email} attempted unauthorized access to ${url}`);

    try {
      await this.prisma.auditLog.create({
        data: {
          action: 'PERMISSION_DENIED',
          entity: 'PermissionGuard',
          path: url,
          method: method,
          userId: user.id,
          userEmail: user.email,
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: userAgent,
          status: LogStatus.DENIED, 
          severity: Severity.HIGH,  // Automatic escalation for security violations
          payload: {
            required_permissions: required,
            granted_permissions: user.permissions,
            attempted_url: url
          }
        }
      });
    } catch (err) {
      this.logger.error(`❌ [SOC_FAILURE] Failed to persist audit trail: ${err.message}`);
    }
  }
}