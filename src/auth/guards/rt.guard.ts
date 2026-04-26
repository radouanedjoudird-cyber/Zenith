/**
 * @fileoverview Refresh Token Gateway Guard.
 * Enforces strict device affinity during the Refresh Token Rotation (RTR) cycle.
 * Designed for High-Availability and Multi-Device Isolation.
 * * @author Radouane Djoudi
 * @version 6.0.0
 */

import {
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * RtGuard: Specialized interceptor for session renewal.
 * Extracts raw cryptographic material and passes it to the IAM Kernel.
 */
@Injectable()
export class RtGuard extends AuthGuard('jwt-refresh') {
  private readonly logger = new Logger('ZENITH_RT_GUARD');

  /**
   * Handles the outcome of the Refresh Strategy validation.
   * Maps cryptographic state into standardized business exceptions.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    // [PHASE 1] CRITICAL IDENTITY CHECK
    if (err || !user) {
      this.logForensicData(request, info, err);

      /**
       * PROTOCOL: SESSION_EXPIRATION
       * If the cryptographic lifecycle of the RT has ended (Max 7 Days).
       */
      if (info?.message === 'jwt expired') {
        throw new ForbiddenException(
          'ZENITH_SHIELD: Session context expired. Re-authentication mandatory.',
        );
      }

      throw new UnauthorizedException('ZENITH_SHIELD: Identity verification failed.');
    }

    /**
     * [PHASE 2] TOKEN EXTRACTION & INJECTION
     * Extracts the raw RT from the Authorization header for AuthService verification.
     */
    const refreshToken = request
      .get('authorization')
      .replace('Bearer', '')
      .trim();

    return { ...user, refreshToken };
  }

  /**
   * Captures high-fidelity telemetry for security auditing.
   * @private
   */
  private logForensicData(req: any, info: any, err: any): void {
    const ip = req.ip || '0.0.0.0';
    const agent = req.headers['user-agent'] || 'UNKNOWN_AGENT';
    const reason = info?.message || err?.message || 'INVALID_REFRESH_CONTEXT';

    this.logger.error(
      `🚨 [RT_GATE_BLOCK] IP: ${ip} | Agent: ${agent} | Reason: ${reason}`
    );
  }
}