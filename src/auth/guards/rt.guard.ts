import {
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * ZENITH REFRESH GUARD - KERNEL v4.0
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * ROLE IN ARCHITECTURE:
 * This Guard acts as the primary interceptor for the Refresh Token Rotation (RTR).
 * It bridges the gap between Passport's cryptographic validation and our
 * Service-level 'Reuse Detection' logic.
 * * SECURITY COMPLIANCE:
 * 1. FALLTHROUGH_PROTECTION: Ensures no unauthenticated request hits the controller.
 * 2. AUDIT_TRAIL: Logs every failed attempt with IP metadata for forensics.
 * 3. ERROR_SHIELDING: Masks internal errors to prevent side-channel leakage.
 */
@Injectable()
export class RtGuard extends AuthGuard('jwt-refresh') {
  private readonly logger = new Logger('Zenith-RT-Guard');

  /**
   * REQUEST HANDLER INTERCEPTOR
   * ---------------------------
   * Overrides the default behavior to provide granular error handling.
   * This is where we decide if a failure is a simple 401 or a critical breach.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // 1. ATOMIC CHECK: If the Passport strategy found a critical cryptographic error
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'] || '0.0.0.0';

      /**
       * FORENSIC LOGGING:
       * Capturing the exact reason for failure (Expired, Malformed, Missing).
       */
      this.logger.error(
        `🚨 [SECURITY_ALERT] RT Gate Blocked | IP: ${ip} | Reason: ${info?.message || 'NULL_TOKEN'}`,
      );

      /**
       * EXCEPTION DIFFERENTIATION:
       * If the token is expired, we throw a 403 to force the client to re-login,
       * preventing 'Infinite Refresh' loops that hackers might exploit.
       */
      if (info?.message === 'jwt expired') {
        throw new ForbiddenException('Zenith Guard: Token has expired. Immediate re-authentication required.');
      }

      /**
       * GENERIC SHIELD:
       * Throwing a 401 for missing or malformed tokens to maintain stealth.
       */
      throw new UnauthorizedException('Zenith Guard: Session access denied.');
    }

    /**
     * PASS-THROUGH:
     * If the token is cryptographically valid, we attach the user object 
     * (which includes the raw RT from RtStrategy) to the request context.
     */
    return user;
  }
}