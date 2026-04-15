import {
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * ZENITH IDENTITY GATEWAY - REFRESH CONTEXT GUARD v5.0
 * -----------------------------------------------------------------------------
 * @class RtGuard
 * @description Primary security interceptor for the Refresh Token Rotation (RTR) lifecycle.
 * This guard ensures that only cryptographically valid Refresh Tokens reach the 
 * multi-device session orchestration layer.
 * * * ARCHITECTURAL STANDARDS:
 * 1. DEFENSE_IN_DEPTH: Acts as the first layer of the dual-verification protocol.
 * 2. EXCEPTION_MAPPING: Standardizes security rejections for consistent UI/UX state control.
 * 3. FORENSIC_TELEMETRY: Provides high-fidelity logging for SIEM and security auditing.
 * 4. MULTI_DEVICE_AWARE: Optimized for concurrent session validation.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class RtGuard extends AuthGuard('jwt-refresh') {
  private readonly logger = new Logger('ZENITH_RT_GUARD');

  /**
   * @method handleRequest
   * @description Intercepts and refines the outcome of the Passport strategy validation.
   * Maps low-level JWT errors into Zenith-standard business exceptions.
   * * @param err - Internal Passport error
   * @param user - Identity payload (hydrated by RtStrategy)
   * @param info - Cryptographic metadata (e.g., expiration details)
   * @param context - Execution context for HTTP metadata extraction
   * * @returns {any} The validated identity payload including the raw RT.
   * @throws {ForbiddenException | UnauthorizedException} Based on the failure vector.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // [PHASE 1] INGRESS VALIDATION
    // Check for underlying strategy errors or complete absence of identity payload.
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'] || '0.0.0.0';
      const userAgent = request.headers['user-agent'] || 'UNKNOWN_AGENT';

      /**
       * SECURITY TELEMETRY:
       * Capturing precise failure vectors for real-time threat detection.
       */
      const failureReason = info?.message || (err ? err.message : 'NULL_TOKEN_INGRESS');
      
      this.logger.error(
        `🚨 [SECURITY_BREACH_ATTEMPT] RT Gate Blocked | IP: ${ip} | Agent: ${userAgent} | Reason: ${failureReason}`,
      );

      /**
       * PROTOCOL: SESSION_EXPIRATION (403)
       * Triggered when the cryptographic lifespan of the RT ends.
       * Instruction to Frontend: Purge all local identity state and redirect to /login.
       */
      if (info?.message === 'jwt expired') {
        throw new ForbiddenException(
          'ZENITH_SHIELD: Session context expired. Re-authentication mandatory.',
        );
      }

      /**
       * PROTOCOL: ACCESS_DENIED (401)
       * Triggered on malformed, missing, or tampered tokens.
       * Maintains a high security posture by providing generic rejection messages.
       */
      throw new UnauthorizedException('ZENITH_SHIELD: Identity verification failed.');
    }

    /**
     * [PHASE 2] IDENTITY PASS-THROUGH
     * The user object now contains the sub (ID) and the raw refreshToken.
     * It is passed to the AuthService for the final DB-level 'Reuse Detection' check.
     */
    return user;
  }
}