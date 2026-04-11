import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH REFRESH TOKEN STRATEGY - ARCHITECTURE v3.1
 * -----------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * DESIGN PRINCIPLE: Dual-Layer Identity Verification.
 * 1. LAYER 1 (Stateless): Passport-JWT verifies digital signature & expiration.
 * 2. LAYER 2 (Stateful): Raw token extraction for "Reuse Detection" against DB hash.
 * * * SECURITY COMPLIANCE:
 * - RFC 6749 Section 10.4 (Refresh Token Rotation).
 * - Cryptographic Isolation: Dedicated RT_SECRET to prevent type-confusion.
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger('Zenith-RT-Strategy');

  constructor(config: ConfigService) {
    const refreshSecret = config.get<string>('RT_SECRET');

    /**
     * FAIL-FAST SECURITY CHECK:
     * Prevents the engine from starting if the cryptographic secret is missing.
     * This is critical for maintaining the integrity of the 7-day session window.
     */
    if (!refreshSecret) {
      throw new Error('🛡️ ZENITH_CORE_ERROR: RT_SECRET is missing in environment registry.');
    }

    super({
      // EXTRACTOR: Standard Bearer Token extraction from the 'Authorization' header.
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      
      // EXPIRATION: Mandatory rejection for tokens outside the expiration window.
      ignoreExpiration: false, 
      
      // ISOLATION: Refresh tokens MUST use a different secret from Access tokens.
      secretOrKey: refreshSecret,
      
      // CONTEXT INJECTION: Mandatory for Layer 2 'Reuse Detection' logic in AuthService.
      passReqToCallback: true,
    });
  }

  /**
   * IDENTITY HYDRATION & EXTRACTION:
   * Bridges the gap between stateless JWT validation and stateful security logic.
   * * @param req The incoming Express request object.
   * @param payload The decoded high-entropy JWT payload.
   */
  async validate(req: Request, payload: any) {
    /**
     * ATOMIC EXTRACTION:
     * We capture the original, encoded JWT string. This 'raw' token is essential
     * for the 'bcrypt.compare' operation against the database-stored hash.
     */
    const authHeader = req?.get('authorization');
    const refreshToken = authHeader?.replace(/Bearer/i, '').trim();

    /**
     * SECURITY TRIGGER:
     * Valid signature but failed extraction indicates a malformed header
     * or a specialized injection attempt.
     */
    if (!refreshToken) {
      this.logger.error(`🚨 [AUTH_FAIL] RT Extraction failed for subject: ${payload.sub}`);
      throw new ForbiddenException('Zenith Shield: Refresh context compromised.');
    }

    /**
     * UNIFIED IDENTITY MAPPING:
     * Injects the raw refreshToken into the request context (req.user).
     * This allows the downstream AuthService to perform the RTR verification.
     */
    return {
      sub: payload.sub,           // Legacy alignment (Standard JWT Claim)
      id: payload.sub,            // Modern developer-friendly alias
      email: payload.email,
      role: payload.role,
      permissions: payload.perms, // PBAC consistency
      refreshToken,               // Essential for the "Burn-on-Use" protocol
    };
  }
}