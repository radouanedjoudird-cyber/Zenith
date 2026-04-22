/**
 * ============================================================================
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v7.1
 * ============================================================================
 * @module AppModule
 * @description Central Kernel for Enterprise Infrastructure Orchestration.
 * * ARCHITECTURAL DESIGN (FAANG COMPLIANT):
 * 1. DEFENSE-IN-DEPTH: Tiered security via Throttler -> AtGuard -> Permissions.
 * 2. CLOUD-NATIVE RELIABILITY: Integrated Health Probes & Stress Simulation.
 * 3. ZERO-TOUCH OBSERVABILITY: Automated telemetry for KEDA predictive scaling.
 * * @author Radouane Djoudi
 * @version 7.1.0 (Reliability Phase)
 * ============================================================================
 */

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

// --- INFRASTRUCTURE & RELIABILITY LAYER ---
import { MonitoringModule } from './common/monitoring/monitoring.module';
import { InfraModule } from './infra/infra.module'; // <--- NEW: Reliability Engine
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
     * High-performance orchestration with variable expansion and caching.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      expandVariables: true,
    }),

    /**
     * OBSERVABILITY PLANE:
     * Manual Prometheus registry for high-fidelity SLIs collection.
     */
    MonitoringModule,

    /**
     * RELIABILITY & CLOUD-NATIVE DIAGNOSTICS:
     * Orchestrates Liveness/Readiness probes and Stress testing simulation.
     * Essential for Kubernetes pod lifecycle management.
     */
    InfraModule,

    /**
     * ANTI-DOS ENGINE:
     * Distributed rate-limiting to prevent resource starvation.
     */
    ThrottlerModule.forRoot([
      {
        name: 'standard_flow',
        ttl: 60000,   // 1 Minute
        limit: 150,   
      }, 
      {
        name: 'critical_auth',
        ttl: 60000,   
        limit: 5,     // Hardened against brute-force attacks
      }
    ]),

    /**
     * DATA PERSISTENCE & DOMAIN LOGIC:
     */
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  providers: [
    /**
     * LAYER 1: TRAFFIC SHAPING
     * Immediate rejection of non-compliant traffic patterns.
     */
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },

    /**
     * LAYER 2: IDENTITY VERIFICATION (Zero-Trust)
     * Mandatory JWT validation across the entire API surface.
     */
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },

    /**
     * LAYER 3: AUTHORIZATION (PBAC)
     * Fine-grained permission evaluation for secure resource access.
     */
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },

    /**
     * PIPELINE 1: FORENSIC TELEMETRY
     * Captures audit trails for security compliance and state changes.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditInterceptor,
    },

    /**
     * PIPELINE 2: PERFORMANCE TELEMETRY
     * Real-time metrics injection for Prometheus/KEDA orchestration.
     * Strategically placed last to measure cumulative execution latency.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: MonitoringInterceptor,
    },
  ],
})
export class AppModule {}