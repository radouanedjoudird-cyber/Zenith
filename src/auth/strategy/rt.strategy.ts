import { ForbiddenException, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH REFRESH TOKEN STRATEGY
 * -----------------------------
 * RESPONSIBILITY: Manages long-term sessions and Token Rotation.
 * SECURITY: Extracts raw token for secure database comparison (Hashed RT).
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.RT_SECRET || 'zenith-refresh-secret-2026',
      passReqToCallback: true, // Crucial for getting the raw token string
    });
  }

  /**
   * REFRESH TOKEN VALIDATION & EXTRACTION
   * Ensures the token is present in the headers for forensic checking.
   */
  validate(req: Request, payload: any) {
    const refreshToken = req?.get('authorization')?.replace('Bearer', '').trim();

    if (!refreshToken) {
      throw new ForbiddenException('Zenith Security: Refresh token is missing or malformed');
    }

    return {
      ...payload,
      refreshToken,
    };
  }
}