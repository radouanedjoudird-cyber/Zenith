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
 * SECURE AUTHENTICATION MODULE
 * SECURITY STRATEGY:
 * 1. Explicit Dependency: PrismaModule is explicitly imported to ensure
 *    database access is always available, regardless of global scope changes.
 * 2. Async JWT Configuration: Secret is loaded via ConfigService at startup,
 *    never hardcoded. This is the industry standard for secret management.
 * 3. Dual Strategy: Two separate Passport strategies handle access tokens
 *    and refresh tokens independently to prevent token type confusion attacks.
 * 4. Sessionless Auth: Passport is configured for stateless JWT to prevent
 *    Session Hijacking attacks.
 */
@Module({
  imports: [
    /**
     * PASSPORT MODULE:
     * Configured for stateless JWT authentication.
     * session: false explicitly disables server-side sessions.
     */
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),

    /**
     * PRISMA MODULE (Explicit Import):
     * Even though PrismaModule is @Global(), we import it explicitly here.
     * This makes the dependency clear and ensures the module works correctly
     * even if the @Global() decorator is removed in the future.
     */
    PrismaModule,

    /**
     * JWT MODULE (Async Configuration):
     * We use registerAsync instead of register({}) to safely load the
     * JWT_SECRET from environment variables via ConfigService.
     * This prevents the secret from being hardcoded or undefined at startup.
     */
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,

    /**
     * DUAL STRATEGY PROVIDERS:
     * JwtStrategy  → validates access tokens  (JWT_SECRET, 15 minutes)
     * RtStrategy   → validates refresh tokens (JWT_REFRESH_SECRET, 7 days)
     * Keeping them separate prevents token type confusion attacks.
     */
    JwtStrategy,
    RtStrategy,
  ],
  exports: [
    // AuthService is kept private by default (Least Privilege Principle).
    // Export it only if other modules require authentication checks.
  ],
})
export class AuthModule {}
