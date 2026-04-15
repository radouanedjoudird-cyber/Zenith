import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH IDENTITY INFRASTRUCTURE - REFRESH CONTEXT STRATEGY v5.0
 * -----------------------------------------------------------------------------
 * @class RtStrategy
 * @description High-integrity validation layer for multi-device session persistence.
 * This strategy orchestrates the "Dual-Layer Verification" protocol, bridging 
 * stateless JWT claims with stateful database integrity checks.
 * * * ARCHITECTURAL STANDARDS:
 * 1. CRYPTO_ISOLATION: Strict enforcement of RT_SECRET vs AT_SECRET boundaries.
 * 2. RTR_ENABLED: Injects raw token strings for the 'Burn-on-Use' rotation logic.
 * 3. COMPLIANCE: Adheres to OAuth 2.0 and NIST security recommendations.
 * 4. MULTI_DEVICE: Optimized for session-specific identification.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger('ZENITH_RT_STRATEGY');

  constructor(config: ConfigService) {
    const refreshSecret = config.get<string>('RT_SECRET');

    /**
     * KERNEL_INTEGRITY_CHECK:
     * Prevents service instantiation if the cryptographic registry is incomplete.
     */
    if (!refreshSecret) {
      throw new Error('CRITICAL_CONFIG_ERROR: RT_SECRET missing in environment registry.');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Strict temporal validation
      secretOrKey: refreshSecret,
      /**
       * @property passReqToCallback
       * @description Vital for 'Reuse Detection'. Enables extraction of the raw 
       * JWT string to perform Argon2id verification against the Session Registry.
       */
      passReqToCallback: true,
    });
  }

  /**
   * @method validate
   * @description Hydrates the execution context with decoded identity and raw RT artifacts.
   * * @param {Request} req - The incoming HTTP execution context.
   * @param {any} payload - Decoded high-entropy claims (JWT Sub, Email, Role, Perms).
   * @returns {Object} Hydrated Identity Object for req.user.
   * @throws {ForbiddenException} On header corruption or extraction failure.
   */
  async validate(req: Request, payload: any) {
    /**
     * @protocol ATOMIC_TOKEN_EXTRACTION:
     * Captures the raw encoded JWT string directly from the Authorization header.
     * This is the 'Pre-image' required for the stateful verify operation.
     */
    const authHeader = req?.get('authorization');
    const refreshToken = authHeader?.replace(/Bearer/i, '').trim();

    /**
     * SECURITY_GATE_TRIGGER:
     * Detects malformed headers where the digital signature might be valid 
     * but the transmission protocol is compromised.
     */
    if (!refreshToken) {
      this.logger.error(`SECURITY_EVENT [RT_EXTRACTION_FAILURE]: Subject ID: ${payload.sub}`);
      throw new ForbiddenException('ZENITH_GUARD: Identity context compromised.');
    }

    /**
     * AUDIT_IDENTITY_HYDRATION:
     * Synchronizes the identity context with the application lifecycle.
     * Maps the 'sub' claim to the 'id' field for consistency across the engine.
     */
    return {
      id: payload.sub,            // Unified identity identifier
      email: payload.email,
      role: payload.role,
      permissions: payload.perms, // PBAC consistency matrix
      refreshToken,               // Essential payload for Multi-Device Rotation
    };
  }
}