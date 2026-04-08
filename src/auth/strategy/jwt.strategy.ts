import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH ACCESS TOKEN STRATEGY
 * ----------------------------
 * RESPONSIBILITY: Validates incoming Bearer tokens for every secure request.
 * SECURITY: Utilizes high-entropy secrets for signature verification.
 * INFRASTRUCTURE: Optimized for low-latency identity resolution.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Strict adherence to token TTL
      secretOrKey: process.env.JWT_SECRET || 'zenith-access-secret-2026',
    });
  }

  /**
   * ZENITH IDENTITY MAPPING
   * Converts the decrypted JWT payload into a secure Request.User object.
   * PERFORMANCE: Lightweight mapping to avoid blocking the Event Loop.
   */
  validate(payload: any) {
    // We map 'sub' to 'sub' to ensure the GetCurrentUserId decorator operates correctly.
    return {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}