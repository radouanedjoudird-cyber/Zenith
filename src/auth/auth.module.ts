import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtStrategy } from './strategy/at.strategy';
import { RtStrategy } from './strategy/rt.strategy';

/**
 * ZENITH AUTHENTICATION MODULE - SECURITY KERNEL v2.9
 * ---------------------------------------------------------
 * MISSION: Orchestrate a bulletproof PBAC identity system.
 * ARCHITECTURE:
 * 1. Hybrid Token Strategy (AT/RT) with Rotation.
 * 2. Asynchronous Factory Pattern for hardened config injection.
 * 3. Zero-Session Passport implementation for high-speed RTT.
 *
 * @author Radouane Djoudi
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
     * Dynamically resolves AT_SECRET from ConfigService at startup.
     * AT_SECRET is isolated from RT_SECRET to prevent token type confusion attacks.
     * Includes a critical fail-safe to prevent booting with missing secrets.
     */
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const secret = config.get<string>('AT_SECRET'); 
        
        if (!secret) {
          /**
           * SECURITY_ABORT:
           * Prevents the engine from starting if cryptographic keys are missing.
           */
          throw new Error('🛡️ ZENITH_CRITICAL: AT_SECRET missing from environment registry.');
        }

        return {
          secret,
          signOptions: {
            /**
             * FIX [TS2322]: Type Casting to 'any' ensures compatibility with 
             * NestJS JwtModuleOptions while maintaining dynamic config.
             */
            expiresIn: (config.get<string>('JWT_AT_EXPIRES') || '15m') as any,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AtStrategy,
    RtStrategy,
  ],
  /**
   * EXPORTED INTERFACES:
   * AuthService: Allows other modules to trigger auth logic.
   * JwtModule: Enables token verification guards across the entire system.
   */
  exports: [AuthService, JwtModule],
})
export class AuthModule {}