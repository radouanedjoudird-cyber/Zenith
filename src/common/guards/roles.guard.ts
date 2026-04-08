import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../enums/role.enum';

/**
 * ZENITH AUTHORIZATION GUARD (RBAC SYSTEM)
 * ----------------------------------------
 * @description
 * Intercepts the request and compares the user's role against the 
 * required roles defined via @Roles decorator.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // 1. REFLECTION: Extract role metadata from current context (Method or Class)
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // 2. BYPASS: If no @Roles decorator is found, access is permitted.
    if (!requiredRoles) {
      return true;
    }

    // 3. CONTEXT: Retrieve the user object populated by JwtStrategy
    const { user } = context.switchToHttp().getRequest();

    /**
     * 4. RBAC LOGIC:
     * Strict check to ensure the user exists and possesses an authorized role.
     */
    const hasAuthorizedRole = user && user.role && requiredRoles.includes(user.role);

    if (!hasAuthorizedRole) {
      throw new ForbiddenException('Access denied: Higher administrative privileges required.');
    }

    return true;
  }
}