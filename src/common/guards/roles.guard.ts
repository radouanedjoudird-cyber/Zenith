import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { LogStatus, Severity } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

/**
 * ZENITH ADVANCED AUTHORIZATION GUARD (ENTERPRISE PBAC v5.0)
 * -----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine (Enterprise Edition)
 * MISSION: Enforce Permission-Based Access Control & Detect Privilege Escalation.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('ZENITH_SECURITY_GUARD');

  constructor(
    private reflector: Reflector,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredPermissions) return true;

    const request = context.switchToHttp().getRequest();
    const { user, method, url, ip } = request;
    const userAgent = request.get('user-agent') || 'Unknown Device';

    if (!user || !user.id) {
      this.logger.error(`[CRITICAL] Security Bypass Attempt: Missing identity at ${url}`);
      throw new UnauthorizedException('Zenith Identity: Session context missing.');
    }

    // STRATEGY: SUPER_ADMIN BYPASS
    if (user.role === 'SUPER_ADMIN') return true;

    // DATABASE VERIFICATION: Fetching permissions (Optimized RTT)
    const userWithPermissions = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: {
        permissions: { select: { action: true } },
      },
    });

    const userActions = userWithPermissions?.permissions.map(p => p.action) || [];
    const hasPermission = requiredPermissions.every((perm) => userActions.includes(perm));

    if (!hasPermission) {
      // 🛡️ FORENSIC ENGINE: Detailed violation logging compliant with v5.0 Schema
      await this.handleSecurityViolation(user, method, url, ip, userAgent, requiredPermissions);
      
      throw new ForbiddenException(
        `Zenith Security: Access Denied. Insufficient clearance for [${requiredPermissions.join(', ')}]`,
      );
    }

    return true;
  }

  /**
   * INTERNAL FORENSIC AUDIT:
   * Records security violations for threat hunting and SOC visibility.
   * FIX: Removed 'details' and updated to 'payload', 'status', and 'severity' Enums.
   */
  private async handleSecurityViolation(
    user: any, 
    method: string, 
    url: string, 
    ip: string, 
    userAgent: string, 
    requiredPermissions: string[]
  ) {
    this.logger.warn(`🚨 [PBAC_DENIAL] Identity ${user?.email} lacked clearance for ${url}`);

    try {
      await this.prisma.auditLog.create({
        data: {
          action: 'PERMISSION_DENIED',
          entity: 'RoleGuard',
          path: url,
          method: method,
          userId: user?.id,
          userEmail: user?.email,
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: userAgent,
          status: LogStatus.DENIED,
          severity: Severity.HIGH,
          payload: {
            missing_permissions: requiredPermissions,
            context: 'Access denied by RolesGuard'
          },
        },
      });
    } catch (err) {
      this.logger.error('SOC Persistence Failure: Audit log could not be saved.', err.message);
    }
  }
}