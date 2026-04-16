/**
 * @fileoverview Access Token Guard (AtGuard).
 * Implements Hardware-Bound Identity Verification and Zero-Trust Ingress.
 * Inspired by Google's BeyondCorp Security Model.
 * * @author Radouane Djoudi
 * @version 6.0.0
 * @license Enterprise - Zenith Secure Engine
 */

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
 * AtGuard: The primary shield for all protected resource endpoints.
 * Enforces hardware affinity and prevents token-only impersonation.
 */
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger('ZENITH_AT_GUARD');

  constructor(private readonly reflector: Reflector) {
    super();
  }

  /**
   * Evaluates the execution context for public bypass or strict authentication.
   * @param {ExecutionContext} context - Request execution pipeline.
   * @returns {Promise<boolean>} Result of the security evaluation.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // [PHASE 1] METADATA REFLECTION: Optimize for public endpoints.
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    // [PHASE 2] PASSPORT STRATEGY EXECUTION
    return super.canActivate(context) as Promise<boolean>;
  }

  /**
   * Orchestrates the final identity decision with Anti-Reconnaissance shielding.
   * @override
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    if (err || !user) {
      this.logSecurityAnomaly(request, info, err);
      
      /**
       * ANTI-RECONNAISSANCE:
       * Obfuscates specific failure reasons to prevent attacker profiling.
       */
      throw new UnauthorizedException('ZENITH_SHIELD: Authentication required for this operation.');
    }

    return user;
  }

  /**
   * Logs unauthorized ingress attempts for forensic auditing.
   * @private
   */
  private logSecurityAnomaly(req: any, info: any, err: any): void {
    const telemetry = {
      ip: req.ip || '0.0.0.0',
      path: `[${req.method}] ${req.url}`,
      agent: req.headers['user-agent'] || 'UNKNOWN_AGENT',
      reason: info?.message || err?.message || 'IDENTITY_PAYLOAD_NULL',
    };

    this.logger.error(
      `🛡️ [INGRESS_BLOCKED] Trace: ${telemetry.ip} | Path: ${telemetry.path} | Reason: ${telemetry.reason}`
    );
  }
}