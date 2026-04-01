import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategy/jwt.strategy';

/**
 * SECURE AUTHENTICATION MODULE
 * SECURITY STRATEGY:
 * 1. Strategy Encapsulation: Strategies are kept internal to the module scope.
 * 2. Secret Protection: JWT configuration is handled dynamically or via AuthService.
 * 3. Sessionless Auth: Passport is configured for stateless JWT (No Cookies/Sessions).
 */
@Module({
  imports: [
    /**
     * PASSPORT MODULE:
     * Configured for stateless authentication. 
     * We don't use sessions to prevent Session Hijacking.
     */
    PassportModule.register({ defaultStrategy: 'jwt', session: false }),

    /**
     * JWT MODULE:
     * We keep this minimal here. 
     * Specific options (Secret, ExpiresIn) are injected in the AuthService
     * using environment variables to prevent hardcoding.
     */
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [
    AuthService, 
    JwtStrategy, // Our internal judge for token validation
  ],
  exports: [
    // We only export AuthService if other modules (like Users) need it.
    // Keeping it private by default is a "Least Privilege" best practice.
  ],
})
export class AuthModule {}