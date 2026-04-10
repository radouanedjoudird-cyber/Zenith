import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/prisma.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

/**
 * ZENITH ADVANCED AUTHORIZATION GUARD (ENTERPRISE PBAC v2.2)
 * ---------------------------------------------------------
 * MISSION: Enforce Permission-Based Access Control & Detect Privilege Escalation.
 * * * SECURITY LOGIC:
 * 1. GRANULARITY: Checks for specific actions (e.g., 'USER_DELETE') rather than just roles.
 * 2. SUPER-USER BYPASS: SUPER_ADMIN bypasses all checks for emergency operations.
 * 3. FORENSIC AUDITING: Async logging of unauthorized attempts into Neon DB.
 * 4. PERFORMANCE: Uses selective DB inclusion to minimize RTT.
 * * * @author Radouane Djoudi
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('Zenith-Security-Guard');

  constructor(
    private reflector: Reflector,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    /**
     * METADATA EXTRACTION:
     * Extracts required permissions assigned via @Permissions() decorator.
     */
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // PUBLIC ROUTE: If no permissions are specified, allow access (assuming AuthGuard passed).
    if (!requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const { user, method, url, ip } = request;
    const userAgent = request.get('user-agent') || 'Unknown Device';

    // FAIL-SAFE: Verify identity presence (Prevents Guard misconfiguration issues).
    if (!user || !user.id) {
      this.logger.error(`[CRITICAL] Security Bypass Attempt: Missing identity at ${url}`);
      throw new UnauthorizedException('Zenith Identity: Session context missing.');
    }

    /**
     * STRATEGY: SUPER_ADMIN BYPASS
     * For rapid infrastructure management, SUPER_ADMIN ignores granular checks.
     */
    if (user.role === 'SUPER_ADMIN') {
      return true;
    }

    /**
     * DATABASE VERIFICATION:
     * Fetching specific user permissions from the junction table.
     * PERFORMANCE: Only selecting the 'action' field to reduce payload size.
     */
    const userWithPermissions = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: {
        permissions: {
          select: { action: true },
        },
      },
    });

    const userActions = userWithPermissions?.permissions.map(p => p.action) || [];

    /**
     * PERMISSION EVALUATION:
     * Every required permission must be present in the user's granted actions.
     */
    const hasPermission = requiredPermissions.every((perm) => userActions.includes(perm));

    if (!hasPermission) {
      // FORWARD TO FORENSIC ENGINE: Non-blocking audit trail persistence.
      this.handleSecurityViolation(user, method, url, ip, userAgent, requiredPermissions);
      
      throw new ForbiddenException(
        `Zenith Security: Access Denied. Required Permission: [${requiredPermissions.join(', ')}]`,
      );
    }

    return true;
  }

  /**
   * INTERNAL FORENSIC AUDIT:
   * Records security violations for threat hunting and SOC visibility.
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
          severity: 'CRITICAL',
          status: 'FAILURE',
          userEmail: user?.email,
          userId: user?.id,
          ipAddress: ip,
          userAgent: userAgent,
          details: {
            attemptedUrl: url,
            attemptedMethod: method,
            missingPermissions: requiredPermissions,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } catch (err) {
      this.logger.error('SOC Persistence Failure: Audit log could not be saved.', err.message);
    }
  }
}