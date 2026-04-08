import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy, StrategyOptionsWithRequest } from 'passport-jwt';

/**
 * ZENITH REFRESH TOKEN STRATEGY (JWT-RT)
 * -------------------------------------
 * SECURITY STRATEGY: Token Rotation & Database Hash Comparison.
 * This strategy extracts the RAW refresh token to allow the AuthService
 * to verify it against the hashed version stored in the database.
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    const options: StrategyOptionsWithRequest = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_REFRESH_SECRET')!,
      passReqToCallback: true, // Crucial for raw token extraction
    };
    super(options);
  }

  /**
   * REFRESH VALIDATION:
   * Called after JWT signature is verified. Extracts the raw token from headers.
   * * @param req - The raw Express request object.
   * @param payload - The decoded JWT payload { sub, email }.
   * @returns Integrated user object with raw token.
   */
  async validate(req: Request, payload: { sub: number; email: string }) {
    const authHeader = req.get('Authorization');
    const rawRt = authHeader?.replace('Bearer', '').trim();

    /**
     * SECURITY GUARD: 
     * Immediate rejection if the raw token is missing or malformed.
     */
    if (!rawRt) {
      throw new ForbiddenException('Access Denied: Refresh token extraction failed.');
    }

    /**
     * UNIFIED PAYLOAD:
     * We return a composite object that satisfies all decorators:
     * 1. sub: For @GetCurrentUserId()
     * 2. id: For legacy Prisma queries.
     * 3. refreshToken: For AuthService comparison.
     */
    return {
      ...payload,
      id: payload.sub, // Mapping for internal consistency
      refreshToken: rawRt,
    };
  }
}