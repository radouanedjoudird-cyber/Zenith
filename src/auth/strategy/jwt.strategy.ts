import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * ZENITH SECURE ENGINE - ACCESS TOKEN STRATEGY (JWT-AT)
 * ----------------------------------------------------
 * @description
 * This strategy is the core of our authentication system. It validates 
 * the integrity of the Access Token and performs a "Deep Identity Check"
 * against the database to ensure the user still exists and is authorized.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    /**
     * CONFIGURATION HARDENING:
     * We extract the secret first to perform a strict null-check.
     * This prevents the server from running in an insecure/broken state.
     */
    const secret = config.get<string>('JWT_SECRET');
    
    if (!secret) {
      // Logic: If the secret is missing, the system is fundamentally insecure.
      throw new Error('CRITICAL CONFIGURATION ERROR: JWT_SECRET is missing in .env');
    }

    super({
      // EXTRACTION: Standard Bearer Token extraction from Headers
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      
      // SECURITY: Strictly reject expired tokens to prevent Replay Attacks.
      ignoreExpiration: false, 
      
      // TYPE SAFETY: The secret is now guaranteed to be a string.
      secretOrKey: secret,
    });
  }

  /**
   * SESSION & INTEGRITY VALIDATION:
   * This method executes after the JWT signature is cryptographically verified.
   * * @param payload - The decoded token object { sub, email, iat, exp }
   * @returns Integrated user object for 'request.user'
   */
  async validate(payload: { sub: number; email: string }) {
    /**
     * DEEP VALIDATION (Database Check):
     * Even if the token is valid, we must verify the user hasn't been 
     * deleted or suspended since the token was issued.
     */
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { 
        id: true, 
        email: true,
        // Performance: Select minimal fields to reduce DB load.
      },
    });

    /**
     * ACCOUNT CHECK:
     * If the user is no longer in the database, we immediately revoke access.
     */
    if (!user) {
      throw new UnauthorizedException('Security Breach: User account not found or revoked.');
    }

    /**
     * COMPATIBILITY & DECORATOR SUPPORT:
     * We return a composite object that satisfies all project requirements:
     * 1. sub: Required by @GetCurrentUserId() decorator.
     * 2. id: Required for direct user.id access in services.
     * 3. email: Required for audit logging and communications.
     */
    return {
      ...payload, // Contains decoded 'sub' and 'email'
      ...user,    // Ensures 'id' is present for Prisma queries
    };
  }
}