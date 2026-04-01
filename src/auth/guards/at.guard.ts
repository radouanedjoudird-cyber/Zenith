import {
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * SECURE ACCESS TOKEN GUARD (JWT)
 * SECURITY STRATEGY:
 * 1. Stealth Fail: Provides generic error messages to prevent "Token Brute Forcing".
 * 2. Internal Auditing: Logs unauthorized attempts for the security admin.
 * 3. Scope Protection: Ensures the request context is fully validated before proceeding.
 */
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(AtGuard.name);

  constructor() {
    super();
  }

  /**
   * HANDLE REQUEST
   * Overriding the default behavior to control "Information Exposure".
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // 1. If there's a system error or no user is found/validated
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'];

      /**
       * AUDIT LOGGING:
       * We log the failed attempt internally with the IP address.
       * This is crucial for detecting "Credential Stuffing" or "Token Spraying" attacks.
       */
      this.logger.warn(`Unauthorized access attempt blocked from IP: ${ip} | Reason: ${info?.message || 'Invalid Token'}`);

      /**
       * SECURITY: INFORMATION EXPOSURE PREVENTION
       * We DO NOT return the 'info.message' (like "Token expired" or "Invalid signature") to the client.
       * Doing so tells an attacker exactly what's wrong with their fake token.
       * We return a generic "Unauthorized" message instead.
       */
      throw new UnauthorizedException('Access denied. Authentication required.');
    }

    return user;
  }
}
