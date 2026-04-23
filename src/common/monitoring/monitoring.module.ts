/**
 * ============================================================================
 * ZENITH SECURE KERNEL - INFRASTRUCTURE TELEMETRY MODULE v7.4.0
 * ============================================================================
 * @module MonitoringModule
 * @description Central Hub for Kernel-level observability and Prometheus exports.
 * * DESIGN PRINCIPLES:
 * 1. SINGLETON_REGISTRY: Enforces a unified registry to prevent metric collisions.
 * 2. IDEMPOTENT_INITIALIZATION: Prevents registry clearing on HMR cycles.
 * 3. GLOBAL_SCOPE: Universal availability of monitoring services.
 * ============================================================================
 */

import {
  Controller,
  Get,
  Global,
  Logger,
  Module,
  OnModuleInit,
  Res,
  VERSION_NEUTRAL
} from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { collectDefaultMetrics, register } from 'prom-client';

import { Public } from '../decorators/public.decorator';
import { MonitoringInterceptor } from '../interceptors/monitoring.interceptor';
import { MonitoringService } from './monitoring.service';

/**
 * @class CustomMetricsController
 * @description High-availability telemetry scraper interface.
 */
@ApiTags('Infrastructure & Telemetry')
@Controller({ 
  path: '', 
  version: VERSION_NEUTRAL 
})
export class CustomMetricsController {
  private readonly logger = new Logger('ZENITH_METRICS');

  @Public()
  @Get('metrics')
  @ApiOperation({ summary: 'Prometheus Scrape Point' })
  @ApiResponse({ status: 200, description: 'Metrics stream synchronized.' })
  async index(@Res() res: Response) {
    try {
      res.set('Content-Type', register.contentType);
      res.end(await register.metrics());
    } catch (error) {
      this.logger.error(`[SCRAPE_ERROR] Failed to export metrics: ${error.message}`);
      res.status(500).send('Telemetry synchronization failed');
    }
  }
}

@Global()
@Module({
  controllers: [CustomMetricsController],
  providers: [
    MonitoringService,
    /**
     * [INTERCEPTOR_REGISTRATION]:
     * Ensuring the MonitoringInterceptor is a singleton and properly injected.
     */
    MonitoringInterceptor,
    { 
      provide: APP_INTERCEPTOR, 
      useExisting: MonitoringInterceptor 
    },
  ],
  exports: [MonitoringService],
})
export class MonitoringModule implements OnModuleInit {
  private readonly logger = new Logger('Zenith-Infra');

  onModuleInit() {
    /**
     * CRITICAL FIX:
     * We removed 'register.clear()' because it wipes out the metrics 
     * defined in MonitoringService's constructor during NestJS bootstrap.
     */
    try {
      // Setup default Node.js runtime metrics (CPU, Memory, Event Loop)
      collectDefaultMetrics({ 
        prefix: 'zenith_core_',
        labels: { service: 'zenith-backend' } 
      });

      this.logger.log('🚀 [TELEMETRY] Global Observability Engine online.');
    } catch (error) {
      /**
       * Handle cases where metrics are already registered 
       * (common during Hot Module Replacement in development).
       */
      this.logger.warn(`[TELEMETRY_WARN] Runtime metrics already initialized.`);
    }
  }
}