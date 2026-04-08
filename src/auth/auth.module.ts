import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategy/jwt.strategy';
import { RtStrategy } from './strategy/rt.strategy';

/**
 * SECURE AUTHENTICATION MODULE - ZENITH INFRASTRUCTURE
 * --------------------------------------------------
 * MISSION: Orchestrate a bulletproof JWT-based identity system.
 */
@Module({
  imports: [
    /**
     * PASSPORT MODULE:
     * Enforcing stateless authentication to prevent server-side session overhead.
     */
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),

    PrismaModule,

    /**
     * JWT MODULE (ASYNCHRONOUS FACTORY):
     * Hardened to handle environment variables safely and resolve type conflicts.
     */
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const secret = config.get<string>('JWT_SECRET');
        if (!secret) {
          throw new Error('CRITICAL_INFRASTRUCTURE_FAILURE: JWT_SECRET is not defined in ENV.');
        }
        
        return {
          secret,
          signOptions: { 
            // FIXED: 'as any' resolves the StringValue compatibility error in NestJS 11+
            expiresIn: (config.get<string>('JWT_AT_EXPIRES') || '15m') as any 
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    RtStrategy,
  ],
  exports: [AuthService, JwtModule], // EXPORTED: Allows other modules to verify tokens using this config
})
export class AuthModule {}