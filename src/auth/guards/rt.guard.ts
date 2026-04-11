import {
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * ZENITH REFRESH GUARD (RtGuard) - SECURITY KERNEL v4.0
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Acts as the primary interceptor for the Refresh Token Rotation (RTR) cycle.
 * Bridges Passport's cryptographic validation with Service-level 'Reuse Detection'.
 * * * SECURITY COMPLIANCE:
 * 1. FALLTHROUGH_PROTECTION: Ensures no unauthorized ingress to the refresh controller.
 * 2. AUDIT_TRAIL: Logs rejections with IP and forensic metadata for SIEM analysis.
 * 3. EXCEPTION_SHIELDING: Strategically maps 401/403 responses for client-side state control.
 */
@Injectable()
export class RtGuard extends AuthGuard('jwt-refresh') {
  private readonly logger = new Logger('Zenith-RT-Guard');

  /**
   * HANDLE_REQUEST INTERCEPTOR:
   * Overrides the default behavior to provide granular lifecycle control.
   * Maps cryptographic failures to specific, actionable security exceptions.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // [PHASE 1] ATOMIC VALIDATION: Check for strategy errors or missing identity payload
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'] || '0.0.0.0';

      /**
       * FORENSIC LOGGING:
       * Capturing the precise failure vector (Expired, Malformed, Missing)
       * for internal engine telemetry on the HP-ProBook logs.
       */
      const failureReason = info?.message || (err ? err.message : 'NULL_TOKEN_INGRESS');
      
      this.logger.error(
        `🚨 [SECURITY_ALERT] RT Gate Blocked | IP: ${ip} | Reason: ${failureReason}`,
      );

      /**
       * [RTR PROTOCOL - EXCEPTION DIFFERENTIATION]
       * IF EXPIRED (403): Signals the Frontend (Vue.js) to trigger a full logout
       * and purge all local storage/session credentials.
       */
      if (info?.message === 'jwt expired') {
        throw new ForbiddenException(
          'Zenith Guard: Session expired. Immediate re-authentication required.'
        );
      }

      /**
       * [STEALTH MODE]
       * RETURN 401 (Unauthorized): For malformed or missing tokens to keep the
       * system's security posture ambiguous to external reconnaissance probes.
       */
      throw new UnauthorizedException('Zenith Guard: Session access denied.');
    }

    /**
     * [IDENTITY PASS-THROUGH]
     * Returns the user object (Hydrated by RtStrategy with the raw refreshToken)
     * to the request context for the second layer of verification (DB Hash).
     */
    return user;
  }
}