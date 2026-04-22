/**
 * ============================================================================
 * ZENITH SECURE CORE - APPLICATION ORCHESTRATOR v7.3.0
 * ============================================================================
 * @module AppModule
 * @description Central Kernel for Enterprise Infrastructure Orchestration.
 * * * ARCHITECTURAL DESIGN:
 * 1. ZERO-WARNING LOGGING: Uses (.*) pattern to silence path-to-regexp v8.
 * 2. DEFENSE-IN-DEPTH: Layered Guards (Throttler, JWT, Permissions).
 * 3. OBSERVABILITY: Telemetry integration via dedicated Interceptors.
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
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';

// --- SECURITY FILTERS ---
import { AtGuard } from './auth/guards/at.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AuditInterceptor } from './common/interceptors/audit.interceptor';
import { MonitoringInterceptor } from './common/interceptors/monitoring.interceptor';

@Module({
  imports: [
    /**
     * [ENTERPRISE LOGGING]: 
     * Using '(.*)' pattern forRoutes ensures compatibility with modern routing engines
     * and prevents the 'LegacyRouteConverter' warning from triggering.
     */
    LoggerModule.forRoot({
      pinoHttp: {
        transport: process.env.NODE_ENV !== 'production' 
          ? { target: 'pino-pretty', options: { colorize: true, singleLine: true } } 
          : undefined,
        autoLogging: {
          ignore: (req) => {
            const url = req.url ?? '';
            return url.includes('health') || url.includes('metrics');
          },
        },
        redact: ['req.headers.authorization', 'req.body.password'],
      },
      forRoutes: ['(.*)'], 
      exclude: [{ method: RequestMethod.ALL, path: 'api/v1/infra/health' }],
    }),

    ConfigModule.forRoot({ isGlobal: true, cache: true, expandVariables: true }),

    ThrottlerModule.forRoot([{
      name: 'standard_flow',
      ttl: 60000,
      limit: 150,   
    }]),

    MonitoringModule,
    InfraModule,
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AtGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_INTERCEPTOR, useClass: AuditInterceptor },
    { provide: APP_INTERCEPTOR, useClass: MonitoringInterceptor },
  ],
})
export class AppModule {}