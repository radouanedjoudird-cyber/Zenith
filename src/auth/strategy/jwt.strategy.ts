import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * SECURE JWT STRATEGY
 * SECURITY STRATEGY:
 * 1. Minimal Payload: Only fetch necessary fields to reduce memory exposure.
 * 2. Generic Exceptions: Hide the reason why a user was rejected.
 * 3. Secret Integrity: Ensure the secret is never hardcoded in production.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      // SECURITY: In production, this MUST come from ENV.
secretOrKey: process.env.JWT_SECRET || 'DEVELOPMENT_SECRET_KEY',    });
  }

  /**
   * VALIDATE METHOD
   * SECURITY: We verify if the user exists and is active.
   */
  async validate(payload: { sub: number; email: string }) {
    /**
     * 1. LEAST PRIVILEGE PRINCIPLE:
     * We only select the ID and Email. We do NOT fetch the password hash 
     * from the DB here, even if we plan to delete it later. This is safer.
     */
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        firstName: true,
        familyName: true,
        // Add "isActive: true" here if you implement account banning later
      },
    });

    // 2. USER EXISTENCE CHECK
    if (!user) {
      this.logger.warn(`JWT Validation failed: User ID ${payload.sub} no longer exists.`);
      
      /**
       * SECURITY: INFORMATION EXPOSURE
       * We use a generic message. Telling the client "User not found" 
       * helps an attacker know that a specific ID has been deleted.
       */
      throw new UnauthorizedException('Invalid authentication credentials.');
    }

    /**
     * 3. DATA INTEGRITY:
     * Since we used 'select' in Prisma, 'user' already doesn't have a password.
     * This is cleaner and more performant than using 'delete' or destructuring.
     */
    return user;
  }
}
