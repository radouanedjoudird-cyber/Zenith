/**
 * @fileoverview ACCESS TOKEN GUARD (AtGuard) - ENTERPRISE SECURITY SHIELD
 * @version 6.1.0
 * @author Radouane Djoudi
 * @description Implements Zero-Trust Ingress based on Google's BeyondCorp Model.
 * Orchestrates Identity Verification with integrated Anti-Reconnaissance logic.
 */

import {
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { lastValueFrom, Observable } from 'rxjs';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';

/**
 * @class AtGuard
 * @description The primary shield for Zenith resources. 
 * Integrates metadata reflection for public bypass (e.g., Metrics/Health).
 */
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger('ZENITH_AT_GUARD');

  constructor(private readonly reflector: Reflector) {
    super();
  }

  /**
   * Evaluates the execution context for security enforcement.
   * Logic: Metadata Bypass -> Strategy Execution -> Forensic Evaluation.
   * @override
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    /**
     * PHASE 1: METADATA REFLECTION
     * Checks for @Public() marker to allow infrastructure tools (Prometheus/K8s) to pass.
     */
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    /**
     * PHASE 2: PASSPORT STRATEGY EXECUTION
     * Invokes the JWT Strategy. Handles both Observable and Promise returns 
     * to maintain high-performance throughput.
     */
    const result = super.canActivate(context);
    
    if (result instanceof Observable) {
      return lastValueFrom(result);
    }
    
    return result as Promise<boolean>;
  }

  /**
   * Final Identity Decision & Anti-Reconnaissance Shielding.
   * Obfuscates internal errors to prevent system profiling by attackers.
   * @override
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    if (err || !user) {
      this.logSecurityAnomaly(request, info, err);
      
      /**
       * ENTERPRISE POLICY: ANTI-RECONNAISSANCE
       * We throw a standardized exception to avoid leaking token-expiry or signature details.
       */
      throw new UnauthorizedException(
        'ZENITH_SHIELD: Authentication required for this operation.'
      );
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
      reason: info?.message || err?.message || 'IDENTITY_PAYLOAD_NULL',
    };

    this.logger.error(
      `🛡️ [INGRESS_BLOCKED] Trace: ${telemetry.ip} | Path: ${telemetry.path} | Reason: ${telemetry.reason}`
    );
  }
}