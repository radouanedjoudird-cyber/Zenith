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
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v5.0
 * -----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine (Enterprise Edition)
 * * ARCHITECTURAL LAYERS:
 * 1. INGRESS_SHIELD: Rate limiting & Anti-DoS orchestration.
 * 2. IDENTITY_STRatum: Global JWT validation with RTR awareness.
 * 3. PERMISSION_FABRIC: PBAC (Permissions-Based Access Control) enforcement.
 * 4. OBSERVABILITY_PLANE: Advanced forensic auditing & telemetry.
 */
@Module({
  imports: [
    /**
     * CONFIGURATION KERNEL:
     * High-performance environment orchestration with caching.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      expandVariables: true, // Allows using vars inside .env (e.g. DB_URL=${HOST}/...)
    }),

    /**
     * RATE LIMITING ENGINE (ADVANCED ANTI-DOS):
     * Dual-tier protection strategy for distributed infrastructure.
     */
    ThrottlerModule.forRoot([{
      name: 'standard_flow',
      ttl: 60000,   // 1 minute
      limit: 120,   // Increased for high-concurrency micro-frontends
    }, {
      name: 'critical_auth',
      ttl: 60000,   // 1 minute
      limit: 7,     // Strict limit for login/refresh attempts
    }]),

    /**
     * INFRASTRUCTURE & DOMAIN CORE:
     */
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  providers: [
    /**
     * SHIELD 1: NETWORK RESILIENCE
     * Prevents infrastructure exhaustion at the ingress point.
     */
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },

    /**
     * SHIELD 2: GLOBAL AUTHENTICATION (Zero-Trust)
     * Enforces mandatory JWT verification across all endpoints.
     */
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },

    /**
     * SHIELD 3: GRANULAR PBAC AUTHORIZATION
     * Validates domain-specific permissions before handler execution.
     */
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },

    /**
     * TELEMETRY: ADVANCED FORENSIC INTERCEPTOR
     * Captures system-wide state changes and data snapshots for auditing.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },
  ],
})
export class AppModule {}