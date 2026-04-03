import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
  ) {
    super({
      // EXTRACTION: Standard Bearer Token extraction from Headers
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_SECRET')!,
    });
  }

  /**
   * PERFORMANCE VALIDATION: 
   * Runs after the token is verified. We check if user still exists.
   */
  async validate(payload: { sub: number; email: string }) {
    // OPTIMIZATION: Only select the fields we actually need. Never use 'select *'
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { 
        id: true, 
        email: true, 
        firstName: true, 
        familyName: true 
        // We exclude 'password' for security and speed
      },
    });

    if (!user) {
      throw new UnauthorizedException('Security Alert: Token valid but user record not found.');
    }

    return user; // This object becomes 'req.user' in the controller
  }
}