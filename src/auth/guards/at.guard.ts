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
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * SECURITY ARCHITECTURE PRINCIPLES:
 * 1. BYPASS_LOGIC: Implements "Public-First" lookup to optimize RTT (Round Trip Time).
 * 2. STEALTH_RESPONSES: Prevents "Identity Enumeration" via generic 401 shielding.
 * 3. FORENSIC_TELEMETRY: Logs granular failure vectors (IP, Path, Reason) for SIEM audit.
 * 4. FAIL-SAFE_DESIGN: Deny-by-default architecture for unauthenticated ingress.
 */
@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger('Zenith-Security-Guard');

  constructor(private readonly reflector: Reflector) {
    super();
  }

  /**
   * CAN_ACTIVATE INTERCEPTOR:
   * Determines if the current execution context requires JWT evaluation.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    /**
     * [PHASE 1] Metadata Reflection:
     * Check for the presence of the @Public() decorator on the handler or class.
     */
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    /**
     * [OPTIMIZATION] Bypass Strategy:
     * If the endpoint is marked public, we bypass the Passport logic entirely
     * to save CPU cycles and reduce response latency (RTT).
     */
    if (isPublic) {
      return true;
    }

    /**
     * [PHASE 2] Passport Strategy Trigger:
     * Executes the 'AtStrategy' validation logic.
     */
    const canActivateResult = await super.canActivate(context);
    return canActivateResult as boolean;
  }

  /**
   * HANDLE_REQUEST: Orchestrates the final authentication decision.
   * Overrides default behavior to implement 'Anti-Reconnaissance' shielding.
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // [PHASE 3] Atomic Identity Check
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'] || 'UNKNOWN_IP';
      const path = request.url;
      const method = request.method;

      /**
       * INTERNAL FORENSIC LOG:
       * Captures the precise reason (Expired, Malformed, Missing) for internal audit.
       * This stays inside the server logs on your HP-ProBook for your eyes only.
       */
      const failureReason = info?.message || (err ? err.message : 'NULL_IDENTITY_PAYLOAD');
      
      this.logger.error(
        `🛡️ [SECURITY-BREACH] Ingress Blocked | IP: ${ip} | Path: [${method}] ${path} | Reason: ${failureReason}`
      );

      /**
       * [ANTI-RECONNAISSANCE]
       * Production Shield: Never leak 'info.message' to the client.
       * This prevents attackers from profiling our JWT expiration or signature logic.
       */
      throw new UnauthorizedException('Zenith Shield: Access denied. Authentication required.');
    }

    /**
     * [IDENTITY INJECTION]
     * The validated identity (Hydrated by AtStrategy) is attached to req.user.
     */
    return user;
  }
}