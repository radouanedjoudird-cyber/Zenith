import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './auth/guards/at.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';

/**
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v2.8
 * --------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL STRATEGY:
 * 1. SECURE_BY_DEFAULT: All routes require authentication unless marked @Public().
 * 2. DEFENSE_IN_DEPTH: Sequenced Guards (Throttling -> Auth -> Permissions).
 * 3. TELEMETRY_PIPELINE: Global interceptor for forensic state auditing.
 * 4. RESOURCE_QUOTA: Multi-tier rate limiting to prevent infrastructure exhaustion.
 */
@Module({
  imports: [
    /**
     * CONFIGURATION KERNEL:
     * Manages environment variables with high-performance memory caching.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
    }),

    /**
     * RATE LIMITING ENGINE (ANTI-DOS):
     * Implements dual-tier protection:
     * - Standard: General API navigation.
     * - Critical: High-sensitivity endpoints (Auth/Write).
     */
    ThrottlerModule.forRoot([{
      name: 'standard',
      ttl: 60000, 
      limit: 100, 
    }, {
      name: 'critical',
      ttl: 60000,
      limit: 5,   
    }]),

    /**
     * INFRASTRUCTURE & DOMAIN MODULES:
     * Encapsulates persistence layers and business logic.
     */
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  providers: [
    /**
     * LAYER 1: NETWORK GUARD (ThrottlerGuard)
     * Responsibility: Prevents resource exhaustion and brute-force attempts.
     */
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },

    /**
     * LAYER 2: AUTHENTICATION GUARD (AtGuard)
     * Responsibility: Validates identity. Enforces mandatory JWT check globally.
     */
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },

    /**
     * LAYER 3: AUTHORIZATION GUARD (PermissionsGuard)
     * Responsibility: Validates granular PBAC claims injected into req.user.
     */
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },

    /**
     * POST-EXECUTION: AUDIT INTERCEPTOR
     * Responsibility: Captures successful/failed actions for security compliance.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },
  ],
})
export class AppModule {}