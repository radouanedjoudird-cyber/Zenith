/**
 * ============================================================================
 * ZENITH CORE INFRASTRUCTURE - OBSERVABILITY ENGINE
 * ============================================================================
 * @module MonitoringModule
 * @description Manual Prometheus Integration & Global Telemetry Orchestration.
 * * DESIGN RATIONALE (FAANG STANDARDS):
 * 1. DECOUPLED_ARCHITECTURE: Zero dependency on faulty library internal routers.
 * 2. GLOBAL_INTERCEPTION: Automatically attaches MonitoringInterceptor to all 
 * system routes for 100% traffic visibility.
 * 3. REGISTRY_HYGIENE: Mandatory 'register.clear()' to ensure idempotent 
 * behavior during Hot Module Replacement (HMR).
 * 4. PERFORMANCE_ISOLATION: Minimal overhead collection logic to ensure zero 
 * impact on P99 latency.
 * * @author Radouane Djoudi
 * @version 15.0.0
 * @status PRODUCTION_STABLE
 * ============================================================================
 */

import { Controller, Get, Global, Logger, Module, OnModuleInit, Res } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import type { Response } from 'express';
import { collectDefaultMetrics, register } from 'prom-client';
import { Public } from '../decorators/public.decorator';
import { MonitoringInterceptor } from './interceptors/monitoring.interceptor';
import { prometheusProviders } from './metrics/metrics.providers';

/**
 * @class CustomMetricsController
 * @description Standardized Prometheus scrape target.
 * Exposes internal telemetry to the Prometheus scraper (typically port 9090).
 */
@Controller('metrics')
export class CustomMetricsController {
  private readonly logger = new Logger('ZENITH_MONITORING');

  @Public()
  @Get()
  async index(@Res() res: Response): Promise<void> {
    try {
      const metrics = await register.metrics();
      res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.status(200).send(metrics);
    } catch (error) {
      this.logger.error(`[TELEMETRY_PANIC] Aggregation failure: ${error.message}`);
      res.status(500).send('Infrastructure Telemetry Offline');
    }
  }
}

@Global()
@Module({
  controllers: [CustomMetricsController],
  providers: [
    ...prometheusProviders,
    /**
     * GLOBAL_TELEMETRY_INTERCEPTOR:
     * We register the interceptor here using the APP_INTERCEPTOR token.
     * This ensures that EVERY request to the API is tracked without 
     * needing to add @UseInterceptors() to every controller.
     */
    {
      provide: APP_INTERCEPTOR,
      useClass: MonitoringInterceptor,
    },
  ],
  exports: [...prometheusProviders],
})
export class MonitoringModule implements OnModuleInit {
  private readonly logger = new Logger('Zenith-Infra');

  /**
   * ON_MODULE_INIT:
   * Direct link to 'prom-client' for manual metric aggregation.
   * This bypasses the Reflect.defineMetadata bug in NestJS 11 library wrappers.
   */
  onModuleInit() {
    try {
      register.clear(); // Prevents "Metric already registered" errors on reload
      
      collectDefaultMetrics({
        prefix: 'zenith_core_',
        labels: { 
          service: 'zenith-backend',
          env: process.env.NODE_ENV || 'development' 
        },
      });

      this.logger.log('🚀 [MONITORING] Telemetry Engine operational via Direct Link.');
      this.logger.log('🛡️ [MONITORING] Global Interceptor attached to all routes.');
    } catch (error) {
      this.logger.error(`[INIT_FAILURE] Monitoring core failed to start: ${error.message}`);
    }
  }
}