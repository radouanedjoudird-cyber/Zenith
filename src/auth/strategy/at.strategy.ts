import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH ACCESS TOKEN STRATEGY - IDENTITY HYDRATION ENGINE v2.8
 * -------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Provides high-speed, stateless identity & permission resolution.
 * * * SECURITY DESIGN:
 * 1. FAIL_FAST_INITIALIZATION: Blocks bootup if AT_SECRET is missing.
 * 2. PBAC_HYDRATION: Injects permission claims into req.user for zero-DB-hit authorization.
 * 3. TTL_ENFORCEMENT: Strict 15m expiration to minimize token theft window.
 * 4. ISOLATION_PRINCIPLE: Uses a dedicated AT_SECRET to prevent type-confusion attacks.
 */
@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    const atSecret = config.get<string>('AT_SECRET');

    /**
     * CORE SECURITY GATE:
     * If AT_SECRET is null, the entire cryptographic layer is compromised.
     * We force a kernel panic to prevent starting in an insecure state.
     */
    if (!atSecret) {
      throw new Error('🛡️ ZENITH_CORE_ERROR: AT_SECRET is missing in environment registry.');
    }

    super({
      // Strategy: Extract from 'Authorization: Bearer <token>'
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // MANDATORY: Rejects expired tokens immediately at the gate.
      ignoreExpiration: false, 
      // Dedicated secret for Access Tokens ONLY.
      secretOrKey: atSecret,
    });
  }

  /**
   * IDENTITY HYDRATION LOGIC:
   * Maps the encrypted JWT payload to the execution context (req.user).
   * Serves as the "Source of Truth" for PermissionsGuard and @GetCurrentUserId.
   *
   * @param payload { sub: number, email: string, role: string, perms: string[] }
   */
  validate(payload: any) {
    /**
     * STRUCTURAL INTEGRITY SHIELD:
     * Ensures the token payload contains verified identity and permission claims.
     * Failure indicates a malformed token or a cross-protocol attack attempt.
     */
    if (!payload.sub || !payload.perms) {
      throw new UnauthorizedException('Zenith Shield: Malformed or compromised security context.');
    }

    /**
     * UNIFIED IDENTITY MAPPING:
     * Normalizing the identity object for global application compatibility.
     * Injects 'permissions' for O(1) authorization checks in downstream Guards.
     */
    return {
      sub: payload.sub,           // Legacy standard for subject ID
      id: payload.sub,            // Modern developer-friendly alias
      email: payload.email,
      role: payload.role,
      permissions: payload.perms, // PBAC: Granular claims for zero-latency checks
    };
  }
}