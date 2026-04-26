/**
 * ============================================================================
 * ZENITH IDENTITY HYDRATION ENGINE - AT STRATEGY
 * ============================================================================
 * @module AtStrategy
 * @version 7.4.0
 * @description Orchestrates stateless identity resolution and permission injection.
 * * ARCHITECTURAL RATIONALE:
 * 1. CRYPTOGRAPHIC_INTEGRITY: Validates Access Tokens using dedicated secrets.
 * 2. ZERO_LATENCY_AUTHORIZATION: Hydrates req.user with 'perms' for O(1) checks.
 * 3. IDENTITY_NORMALIZATION: Standardizes subject claims across the micro-kernel.
 * ============================================================================
 */

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly config: ConfigService) {
    const atSecret = config.get<string>('AT_SECRET');

    /**
     * CRITICAL_GATE_CHECK:
     * Prevention of insecure bootstrap. If AT_SECRET is undefined, 
     * the system must halt to prevent cryptographic bypass.
     */
    if (!atSecret) {
      throw new Error('🛡️ ZENITH_CORE_ERROR: AT_SECRET is not defined in the environment.');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Strict TTL enforcement (typically 15m)
      secretOrKey: atSecret,
    });
  }

  /**
   * @method validate
   * @description Hydrates the execution context with normalized identity claims.
   * @param payload { sub: string, email: string, role: string, perms: string[] }
   * @returns Authorized identity object injected into req.user
   */
  validate(payload: any) {
    /**
     * MALFORMED_TOKEN_PROTECTION:
     * Rejects tokens that lack the mandatory 'sub' or 'perms' claims.
     * This protects against type-confusion and protocol downgrade attacks.
     */
    if (!payload.sub || !payload.perms) {
      throw new UnauthorizedException('ZENITH_SHIELD: Security context integrity failure.');
    }

    /**
     * IDENTITY_NORMALIZATION_MAP:
     * Standardizes the user object for downstream consumers (Guards/Controllers).
     * Mapping 'perms' from payload to both 'permissions' (legacy) and 'perms' (modern).
     */
    return {
      id: payload.sub,            // Modern ID reference
      sub: payload.sub,           // Standard JWT subject reference
      email: payload.email,
      role: payload.role,         // Dynamic Role Name (e.g., "ADMIN")
      perms: payload.perms,       // Modern claim reference used in PermissionsGuard v7
      permissions: payload.perms, // Legacy alias for backward compatibility
    };
  }
}