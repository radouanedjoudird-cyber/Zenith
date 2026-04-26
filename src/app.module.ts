/**
 * ============================================================================
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v7.4.0
 * ============================================================================
 * @module AppModule
 * @description Central Kernel for Enterprise Infrastructure Orchestration.
 * * * ARCHITECTURAL DESIGN RATIONALE:
 * 1. DECOUPLED_OBSERVABILITY: Telemetry (MonitoringInterceptor) is handled 
 * internally by MonitoringModule to ensure Singleton consistency.
 * 2. DEFENSE_IN_DEPTH: Ordered execution of Guards (RateLimit -> Auth -> RBAC).
 * 3. NOISE_REDUCTION: Pino logger is optimized to exclude high-frequency 
 * infrastructure heartbeat (health/metrics).
 * ============================================================================
 */

import { Module, RequestMethod } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';

// --- CORE LAYER ---
import { AppController } from './app.controller';
import { AppService } from './app.service';

// --- INFRASTRUCTURE & DOMAIN ---
import { AuthModule } from './auth/auth.module';
import { MonitoringModule } from './common/monitoring/monitoring.module';
import { InfraModule } from './infra/infra.module';
import { UsersModule } from './users/users.module';

// --- SECURITY FILTERS ---
import { AtGuard } from './auth/guards/at.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';

@Module({
  imports: [
    /**
     * [ENTERPRISE_LOGGING]: 
     * Orchestrates structured logging via Pino.
     * SILENCE_POLICY: Excludes infrastructure telemetry to maintain log clarity.
     * REDACTION: Protects PII and sensitive tokens from leaking into logs.
     */
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.NODE_ENV !== 'production' ? 'debug' : 'info',
        transport: process.env.NODE_ENV !== 'production' 
          ? { target: 'pino-pretty', options: { colorize: true, singleLine: true } } 
          : undefined,
        autoLogging: {
          ignore: (req) => {
            const url = req.url ?? '';
            return url.includes('health') || url.includes('metrics') || url.includes('favicon.ico');
          },
        },
        redact: {
          paths: [
            'req.headers.authorization', 
            'req.body.password', 
            'req.body.refreshToken',
            'req.body.accessToken'
          ],
          // FIX: Changed 'placeholder' to 'censor' to comply with Pino Typescript definitions
          censor: '[REDACTED_SENSITIVE_DATA]' 
        },
      },
      forRoutes: ['(.*)'], 
      exclude: [{ method: RequestMethod.ALL, path: 'api/v1/infra/health' }],
    }),

    /**
     * [CONFIG_ENGINE]: Centralized environment variable management with caching.
     */
    ConfigModule.forRoot({ 
      isGlobal: true, 
      cache: true, 
      expandVariables: true 
    }),

    /**
     * [TRAFFIC_CONTROL]: Mitigates DoS/Brute-force via standard flow throttling.
     */
    ThrottlerModule.forRoot([{
      name: 'standard_flow',
      ttl: 60000,
      limit: 150,   
    }]),

    // Internal Infrastructure & Business Modules
    MonitoringModule,
    InfraModule,
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    /**
     * [SECURITY_GUARDS_HIERARCHY]:
     * Order of execution is critical for kernel performance and security.
     */
    { provide: APP_GUARD, useClass: ThrottlerGuard },    // Phase 1: Rate Limiting
    { provide: APP_GUARD, useClass: AtGuard },          // Phase 2: Authentication
    { provide: APP_GUARD, useClass: PermissionsGuard },   // Phase 3: Authorization (RBAC)

    /**
     * [SYSTEM_INTERCEPTORS]:
     * Note: MonitoringInterceptor is managed by MonitoringModule for Singleton integrity.
     */
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
  ],
})
export class AppModule {}