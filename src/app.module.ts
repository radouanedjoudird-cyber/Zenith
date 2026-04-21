/**
 * ============================================================================
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v7.0
 * ============================================================================
 * @module AppModule
 * @description Central Kernel for Enterprise Infrastructure Orchestration.
 * * ARCHITECTURAL DESIGN (FAANG COMPLIANT):
 * 1. DEFENSE-IN-DEPTH: Layered security via Throttler -> AtGuard -> Permissions.
 * 2. TELEMETRY_AUTO_INJECTION: Global interceptors for Zero-Touch observability.
 * 3. KERNEL_STABILITY: High-performance Config cache & Prisma persistence.
 * * @author Radouane Djoudi
 * @version 7.0.0
 * ============================================================================
 */

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

// --- INFRASTRUCTURE LAYER ---
import { MonitoringModule } from './common/monitoring/monitoring.module';
import { PrismaModule } from './prisma/prisma.module';

// --- DOMAIN LAYER ---
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

// --- SECURITY & CROSS-CUTTING CONCERNS ---
import { AtGuard } from './auth/guards/at.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';
import { MonitoringInterceptor } from './common/interceptors/monitoring.interceptor';

@Module({
  imports: [
    /**
     * CONFIGURATION KERNEL:
     * High-performance orchestration with variable expansion.
     * Cache is enabled to reduce I/O overhead during high-traffic bursts.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      expandVariables: true,
    }),

    /**
     * OBSERVABILITY PLANE (RQ2 SUPPORT):
     * Orchestrates Prometheus telemetry and manual registry links.
     * Centralized here to ensure all domain modules are automatically scraped.
     */
    MonitoringModule,

    /**
     * RATE LIMITING ENGINE (ANTI-DoS STRATEGY):
     * Protects the underlying infrastructure from resource exhaustion attacks.
     * @standard_flow: Optimized for high-throughput mobile/web clients.
     * @critical_auth: Mitigates brute-force and credential stuffing.
     */
    ThrottlerModule.forRoot([
      {
        name: 'standard_flow',
        ttl: 60000,   // 60 Seconds
        limit: 150,   // Balanced for microservices latency
      }, 
      {
        name: 'critical_auth',
        ttl: 60000,   
        limit: 5,     // Hardened for security-first operations
      }
    ]),

    /**
     * DATA PERSISTENCE & BUSINESS DOMAINS:
     */
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  providers: [
    /**
     * LAYER 1: NETWORK RESILIENCE
     * Guards the application boundary against traffic spikes.
     */
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },

    /**
     * LAYER 2: IDENTITY ENFORCEMENT (Zero-Trust)
     * Ensures all requests are authenticated by default.
     * Uses 'Reflector' to allow @Public() overrides where necessary.
     */
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },

    /**
     * LAYER 3: PBAC AUTHORIZATION
     * Evaluates fine-grained permissions after identity is established.
     */
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },

    /**
     * PIPELINE 1: FORENSIC AUDITING
     * Non-blocking capture of state changes for regulatory compliance.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },

    /**
     * PIPELINE 2: TELEMETRY ENGINE
     * Captures SLIs (Service Level Indicators) for the KEDA Autoscaler.
     * This is the technical core of the thesis evaluation phase.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: MonitoringInterceptor,
    },
  ],
})
export class AppModule {}