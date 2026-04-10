import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH ACCESS TOKEN STRATEGY - IDENTITY HYDRATION ENGINE v2.8
 * -------------------------------------------------------------
 * RESPONSIBILITY: High-speed, stateless identity & permission resolution.
 * STRATEGY: Decrypts JWT and hydrates the request context with PBAC claims.
 * PERFORMANCE: Optimized for zero-latency execution (No DB lookups).
 * SECURITY: Strict TTL enforcement to mitigate token theft window.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // MANDATORY: Rejects expired tokens immediately at the gate.
      /**
       * CRYPTOGRAPHIC SECRET:
       * The '!' operator ensures TS that the secret is provided via environment variables.
       */
      secretOrKey: config.get<string>('JWT_SECRET')!, 
    });
  }

  /**
   * ZENITH IDENTITY HYDRATION
   * --------------------------
   * Decodes the encrypted high-entropy payload and attaches it to the execution context (req.user).
   * This logic acts as the "Source of Truth" for PermissionsGuard and @GetCurrentUserId.
   * * @param payload { sub: number, email: string, role: string, perms: string[] }
   * @returns Hydrated user object attached to req.user
   */
  validate(payload: any) {
    /**
     * SECURITY SHIELD: STRUCTURAL INTEGRITY CHECK
     * Ensures the token payload contains the essential identity and permission claims.
     * Failure here indicates a malformed token or a protocol mismatch.
     */
    if (!payload.sub || !payload.perms) {
      throw new UnauthorizedException('Zenith Shield: Malformed or compromised security context.');
    }

    /**
     * UNIFIED IDENTITY MAPPING:
     * Standardizing the user object to ensure seamless integration with 
     * both legacy code (using 'sub') and modern logic (using 'id').
     */
    return {
      sub: payload.sub,           // Internal standard for subject ID
      id: payload.sub,            // Developer-friendly alias
      email: payload.email,
      role: payload.role,
      permissions: payload.perms, // PBAC: Injected permissions for Zero-DB-Hit authorization
    };
  }
}