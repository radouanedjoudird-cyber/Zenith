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
 * This module serves as the central nervous system of the Zenith platform.
 * * STRATEGY FOR HIGH-AVAILABILITY & SECURITY:
 * 1. ZERO-TRUST ARCHITECTURE: All routes are guarded by default via Global AtGuard.
 * 2. MULTI-LAYERED DEFENSE: Integrated Throttling, Authentication, and PBAC.
 * 3. PERFORMANCE TUNING: Config caching enabled for ultra-low latency on HP-ProBook.
 * 4. FORENSIC CONTINUITY: Asynchronous telemetry capture for all system state changes.
 * * @author Radouane Djoudi
 * @environment HP-ProBook / Linux-Production
 */
@Module({
  imports: [
    /**
     * CONFIGURATION KERNEL:
     * High-speed environment variable management with memory caching.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
    }),

    /**
     * RATE LIMITING ENGINE (ANTI-DOS/BRUTE-FORCE):
     * Protects the infrastructure layer from resource exhaustion and automated attacks.
     */
    ThrottlerModule.forRoot([{
      name: 'standard',
      ttl: 60000, 
      limit: 100, 
    }, {
      name: 'critical',
      ttl: 60000,
      limit: 5,   // Strict limit for sensitive Auth/Write operations.
    }]),

    /**
     * CORE INFRASTRUCTURE:
     * PrismaModule handles connection pooling to Neon DB with optimized RTT.
     */
    PrismaModule,

    /**
     * DOMAIN LOGIC MODULES:
     * Encapsulates the core business logic of the Zenith platform.
     */
    AuthModule,
    UsersModule,
  ],
  providers: [
    /**
     * GLOBAL GUARD 1: RATE LIMITER
     * Priority: High. First line of defense against network-level abuse.
     */
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },

    /**
     * GLOBAL GUARD 2: ACCESS TOKEN VALIDATION (AT)
     * Priority: Critical. Enforces "Secure by Default" strategy across all endpoints.
     * Note: Public routes must be explicitly marked with @Public() decorator.
     */
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },

    /**
     * GLOBAL GUARD 3: PERMISSION-BASED ACCESS CONTROL (PBAC)
     * Priority: Essential. Validates granular permissions for authenticated users.
     */
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },

    /**
     * GLOBAL INTERCEPTOR: FORENSIC TELEMETRY
     * Post-Execution capture for auditing and security compliance.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },
  ],
})
export class AppModule {}