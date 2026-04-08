import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { ROLES_KEY } from '../decorators/roles.decorator';

/**
 * ZENITH ADVANCED AUTHORIZATION GUARD
 * -----------------------------------
 * SECURITY FEATURES:
 * 1. RBAC Validation: Checks user roles against route metadata.
 * 2. Forensic Logging: Automatically logs unauthorized access attempts.
 * 3. High Performance: Early exit for public routes.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger('SecurityGuard');

  constructor(
    private reflector: Reflector,
    private prisma: PrismaService, // Injected for real-time security logging
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const { user, method, url, ip } = request;
    const userAgent = request.get('user-agent') || 'Unknown Device';

    const hasRole = requiredRoles.some((role) => user?.role === role);

    if (!hasRole) {
      /**
       * SECURITY ALERT TRIGGER
       * ----------------------
       * We log this attempt in the console and the database.
       * This data is crucial for identifying 'Horizontal Privilege Escalation' attacks.
       */
      this.logger.warn(
        `SECURITY VIOLATION: User ${user?.email} (Role: ${user?.role}) attempted to access ${method} ${url} from IP ${ip} [Device: ${userAgent}]`
      );

      // Async logging to DB (Don't block the response)
      this.prisma.auditLog.create({
        data: {
          action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
          entity: 'System/RBAC',
          details: {
            attemptedUrl: url,
            requiredRoles,
            userRole: user?.role,
            device: userAgent,
            severity: 'HIGH',
          },
          userId: user?.id,
        },
      }).catch(err => this.logger.error('Failed to save security audit log', err));

      throw new ForbiddenException(
        `Zenith Security: Access Denied. Required Roles: [${requiredRoles.join(', ')}]`,
      );
    }

    return true;
  }
}