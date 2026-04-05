import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy, StrategyOptionsWithRequest } from 'passport-jwt';

/**
 * REFRESH TOKEN STRATEGY:
 * A dedicated Passport strategy for validating refresh tokens.
 * Completely separate from the access token strategy (jwt.strategy.ts)
 * to prevent token type confusion attacks.
 *
 * KEY DIFFERENCE from JwtStrategy:
 * This strategy extracts the RAW refresh token from the Authorization header
 * and attaches it to req.user. This allows AuthService.refreshTokens()
 * to compare it against the stored bcrypt hash in the database.
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    /**
     * EXPLICIT TYPE CASTING:
     * We explicitly type the options as StrategyOptionsWithRequest
     * to satisfy TypeScript's strict type checking while keeping
     * passReqToCallback: true for raw token extraction.
     */
    const options: StrategyOptionsWithRequest = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_REFRESH_SECRET')!,
      passReqToCallback: true,
    };
    super(options);
  }

  /**
   * REFRESH TOKEN VALIDATION:
   * Called automatically by Passport after the JWT signature is verified.
   * We extract the raw token and attach it to the payload so AuthService
   * can validate it against the bcrypt hash stored in the database.
   */
  async validate(req: Request, payload: { sub: number; email: string }) {
    const rawRt = req.get('Authorization')?.replace('Bearer', '').trim();

    /**
     * SECURITY CHECK:
     * If for any reason the raw token cannot be extracted,
     * we immediately reject the request.
     */
    if (!rawRt) {
      throw new ForbiddenException('Access Denied. Refresh token not found.');
    }

    /**
     * PAYLOAD ENRICHMENT:
     * We attach the raw token to the returned object.
     * This becomes req.user in the controller, giving AuthService
     * direct access to both the userId and the raw token for hash comparison.
     */
    return {
      ...payload,
      refreshToken: rawRt,
    };
  }
}