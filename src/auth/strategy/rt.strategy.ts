/**
 * ============================================================================
 * ZENITH IDENTITY INFRASTRUCTURE - REFRESH CONTEXT STRATEGY
 * ============================================================================
 * @module RtStrategy
 * @version 7.4.0
 * @description High-integrity validation layer for multi-device session persistence.
 * * ARCHITECTURAL RATIONALE:
 * 1. DUAL_LAYER_VERIFICATION: Bridges stateless claims with stateful DB checks.
 * 2. RTR_ENGINE: Injects raw token artifacts for 'Burn-on-Use' rotation logic.
 * 3. HARDWARE_AFFINITY: Provides context for device-bound session integrity.
 * ============================================================================
 */

import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger('ZENITH_RT_STRATEGY');

  constructor(private readonly config: ConfigService) {
    const refreshSecret = config.get<string>('RT_SECRET');

    /**
     * KERNEL_INTEGRITY_CHECK:
     * Prevents service instantiation if the cryptographic registry is incomplete.
     * Essential for maintaining the chain of trust.
     */
    if (!refreshSecret) {
      throw new Error('🛡️ ZENITH_CORE_ERROR: RT_SECRET is missing in environment registry.');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Strict temporal enforcement
      secretOrKey: refreshSecret,
      /**
       * @property passReqToCallback
       * @description Crucial for 'Reuse Detection'. Enables extraction of the raw 
       * JWT string for Argon2id comparison against the persistent Session Registry.
       */
      passReqToCallback: true,
    });
  }

  /**
   * @method validate
   * @description Hydrates the execution context with decoded identity and raw RT artifacts.
   * @param req - Inbound HTTP execution context for header extraction.
   * @param payload - Decoded high-entropy claims (sub, email, role, perms).
   */
  async validate(req: Request, payload: any) {
    /**
     * @protocol ATOMIC_TOKEN_EXTRACTION:
     * Captures the raw encoded JWT string directly from the Authorization header.
     * This serves as the 'Pre-image' required for the stateful database verify operation.
     */
    const authHeader = req?.get('authorization');
    const refreshToken = authHeader?.replace(/Bearer/i, '').trim();

    /**
     * SECURITY_GATE_TRIGGER:
     * Rejects requests where the token extraction fails despite a valid signature.
     * Protects against header corruption or injection attempts.
     */
    if (!refreshToken) {
      this.logger.error(`SECURITY_EVENT [RT_EXTRACTION_FAILURE]: Subject ID: ${payload.sub}`);
      throw new ForbiddenException('ZENITH_SHIELD: Refresh context integrity compromised.');
    }

    /**
     * IDENTITY_HYDRATION_LOGIC:
     * Normalizes the identity context for the v7.4.0 Refresh Token Rotation (RTR).
     * Synchronizes claim names with AtStrategy for global consistency.
     */
    return {
      id: payload.sub,            // Primary identity reference
      sub: payload.sub,           // Standard JWT subject claim
      email: payload.email,
      role: payload.role,         // Dynamic role name (e.g., "MANAGER")
      perms: payload.perms,       // Modern PBAC claims mapping
      permissions: payload.perms, // Legacy mapping for backward compatibility
      refreshToken,               // Raw artifact for stateful verification
    };
  }
}