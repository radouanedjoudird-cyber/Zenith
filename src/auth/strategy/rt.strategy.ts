import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

/**
 * ZENITH REFRESH TOKEN STRATEGY - ARCHITECTURE v3.1
 * -----------------------------------------------------------
 * DESIGN PRINCIPLE: Dual-Layer Identity Verification.
 * * LAYER 1 (Stateless): Passport-JWT verifies the signature and expiration 
 * against the cryptographic secret.
 * * LAYER 2 (Stateful): Extracting the raw token string to allow the AuthService 
 * to perform "Reuse Detection" against the database hash.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger('Zenith-RT-Guard');

  constructor(config: ConfigService) {
    const refreshSecret = config.get<string>('JWT_REFRESH_SECRET');

    // SECURITY CHECK: Fail-fast if the system environment is compromised (missing secrets).
    if (!refreshSecret) {
      throw new Error('ZENITH_CORE_ERROR: JWT_REFRESH_SECRET is missing in environment registry.');
    }

    super({
      // EXTRACTOR: We use the standard Bearer Token extraction from the 'Authorization' header.
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      
      // EXPIRATION: Strict mode. If the 7-day window passes, Layer 1 will block the request.
      ignoreExpiration: false, 
      
      // ISOLATION: Refresh tokens must use a different secret from Access tokens.
      secretOrKey: refreshSecret,
      
      // CONTEXT INJECTION: Passing 'req' to validate() is mandatory for Layer 2 security.
      passReqToCallback: true,
    });
  }

  /**
   * IDENTITY HYDRATION & EXTRACTION
   * -------------------------------
   * This method bridge the gap between the stateless JWT and our stateful security logic.
   * * @param req The raw Express request.
   * @param payload The decoded JWT payload (ID, Email, Role, Perms).
   */
  async validate(req: Request, payload: any) {
    /**
     * ATOMIC EXTRACTION:
     * We need the original, encoded JWT string. Why? 
     * Because 'bcrypt.compare' needs the raw string to match it against the DB hash.
     */
    const authHeader = req?.get('authorization');
    const refreshToken = authHeader?.replace(/Bearer/i, '').trim();

    /**
     * IPS TRIGGER:
     * If Passport verified the JWT but we can't extract the string, 
     * this indicates a malformed header or an injection attempt.
     */
    if (!refreshToken) {
      this.logger.error(`🚨 [AUTH_FAIL] Extraction failed for user: ${payload.sub}`);
      throw new ForbiddenException('Zenith Shield: Refresh context compromised.');
    }

    /**
     * UNIFIED IDENTITY OBJECT:
     * We return a rich object that becomes 'req.user'. 
     * Including the 'refreshToken' here is what enables the 'Reuse Detection' 
     * in AuthService.refreshTokens().
     */
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      permissions: payload.perms, // Maintaining Granular PBAC
      refreshToken,               // The 'Secret' required for the next rotation
    };
  }
}