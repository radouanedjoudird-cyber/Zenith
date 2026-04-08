import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * ZENITH IDENTITY STRATEGY (JWT-AT-VALIDATOR)
 * ------------------------------------------
 * @description
 * Reconstructs the 'request.user' object from the Bearer Token.
 * It enforces strict database synchronization for Role-Based Access Control.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    /**
     * SECURITY HARDENING:
     * We ensure the secret is defined or fallback to a critical error.
     */
    const secret = config.get<string>('JWT_SECRET');
    if (!secret) throw new Error('CRITICAL: JWT_SECRET environment variable is not set.');

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  /**
   * AUTHENTICATION CALLBACK:
   * Decodes the payload and injects fresh user data into the request pipeline.
   * @param payload - Decoded JWT claims { sub, email, role }
   */
  async validate(payload: { sub: number; email: string; role: string }) {
    /**
     * REAL-TIME ROLE SYNC:
     * We fetch the current role from the DB to prevent 'Stale Role' privilege escalation.
     */
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { 
        id: true, 
        email: true,
        role: true, // MANDATORY: Required for RolesGuard comparison
      },
    });

    if (!user) {
      throw new UnauthorizedException('Security Breach: Identity context not found.');
    }

    // Attached to Request.user
    return user; 
  }
}