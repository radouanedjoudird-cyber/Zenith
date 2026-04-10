import {
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';

/**
 * ZENITH ACCESS TOKEN GUARD (AtGuard) - SECURITY KERNEL v2.8
 * ---------------------------------------------------------
 * ROLE: Primary gatekeeper for JWT-based session validation.
 * * SECURITY ARCHITECTURE PRINCIPLES:
 * 1. BYPASS LOGIC: Operates with a "Public-First" lookup to optimize RTT (Round Trip Time).
 * 2. STEALTH RESPONSES: Prevents "Identity Enumeration" by masking internal errors with generic 401s.
 * 3. FORENSIC TELEMETRY: Logs granular failure reasons (IP, Path, Reason) for SIEM analysis.
 * 4. FAIL-SAFE DESIGN: Defaults to 'Deny-All' if any part of the validation pipeline fails.
 */
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger('Zenith-Security-Guard');

  constructor(private readonly reflector: Reflector) {
    super();
  }

  /**
   * INTERCEPTOR: Decides if the request should be evaluated for a JWT.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // [PHASE 1] Metadata Reflection: Check if the endpoint is marked as @Public()
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // [OPTIMIZATION] If Public, bypass JWT logic entirely to save CPU cycles.
    if (isPublic) {
      return true;
    }

    // [PHASE 2] Passport Strategy Execution: Trigger the JWT validation strategy.
    return super.canActivate(context) as boolean | Promise<boolean>;
  }

  /**
   * RESPONSE HANDLER: Orchestrates the outcome of the authentication attempt.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'] || 'UNKNOWN_IP';
      const path = request.url;
      const method = request.method;

      // [CRITICAL] Forensic Audit Log: Detailed info for the Admin/Dev (Zenith Engine Internal)
      const failureReason = info?.message || (err ? err.message : 'No JWT Provided');
      this.logger.error(
        `🛡️ [SECURITY-BREACH] Attempt Denied | IP: ${ip} | Path: [${method}] ${path} | Reason: ${failureReason}`
      );

      /**
       * [ANTI-RECONNAISSANCE]
       * Do not return 'info.message' to the client. This prevents attackers from knowing 
       * if a token is expired, malformed, or missing.
       */
      throw new UnauthorizedException('Access denied. Authentication required.');
    }

    // [IDENTITY INJECTION] Payload is validated and attached to the Request object.
    return user;
  }
}