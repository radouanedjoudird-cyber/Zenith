import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtStrategy } from './strategy/at.strategy'; // FIXED: Name consistent with AtStrategy class
import { RtStrategy } from './strategy/rt.strategy';

/**
 * SECURE AUTHENTICATION MODULE - ZENITH INFRASTRUCTURE v2.8
 * ---------------------------------------------------------
 * MISSION: Orchestrate a bulletproof PBAC identity system.
 * ARCHITECTURE: 
 * 1. Hybrid Token Strategy (AT/RT) with Rotation.
 * 2. Asynchronous Factory Pattern for hardened config injection.
 * 3. Zero-Session Passport implementation for high-speed RTT.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Module({
  imports: [
    /**
     * PASSPORT INTEGRATION:
     * Enforcing 'stateless' authentication. Sessions are disabled to maintain 
     * scalability and performance on distributed environments.
     */
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),

    PrismaModule,

    /**
     * JWT INFRASTRUCTURE (ASYNC FACTORY):
     * Dynamically resolves secrets from the ConfigService.
     * Includes a critical fail-safe check to prevent booting with insecure defaults.
     */
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const secret = config.get<string>('JWT_SECRET');
        if (!secret) {
          throw new Error('🛡️ ZENITH_CRITICAL: JWT_SECRET missing from environment registry.');
        }
        
        return {
          secret,
          signOptions: { 
            // FIXED: Casting 'as any' ensures compatibility with NestJS 11+ Duration formats.
            expiresIn: (config.get<string>('JWT_AT_EXPIRES') || '15m') as any 
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AtStrategy, // FIXED: Corrected from JwtStrategy to AtStrategy to match the file export
    RtStrategy,
  ],
  /**
   * EXPORTED INTERFACES:
   * AuthService: Allows other modules (e.g., UsersModule) to trigger auth logic.
   * JwtModule: Enables token verification guards across the entire system.
   */
  exports: [AuthService, JwtModule],
})
export class AuthModule {}