/**
 * ============================================================================
 * ZENITH SECURE KERNEL - TELEMETRY & OBSERVABILITY ORCHESTRATOR v7.4.0
 * ============================================================================
 * @class MonitoringInterceptor
 * @description Advanced Request-Response Lifecycle Instrumentation Engine.
 * * ARCHITECTURAL STANDARDS:
 * 1. DUAL_INSTRUMENTATION: Dispatches metrics to both Summary (P99) and Histogram (SLO).
 * 2. HIGH_RESOLUTION_TIMING: Precision nanosecond measurement via process.hrtime.
 * 3. CARDINALITY_SANITIZATION: Prevents label explosion in Prometheus registry.
 * 4. FAULT_TOLERANT_OBSERVABILITY: Ensures telemetry logic never interrupts the request flow.
 * ============================================================================
 */

import {
  CallHandler,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, finalize, tap } from 'rxjs/operators';
import { MonitoringService } from '../monitoring/monitoring.service';

@Injectable()
export class MonitoringInterceptor implements NestInterceptor {
  private readonly logger = new Logger('ZENITH_TELEMETRY_ENGINE');

  constructor(private readonly telemetry: MonitoringService) {}

  /**
   * @method intercept
   * @description Primary interception logic for the HTTP lifecycle.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Only instrument HTTP traffic
    if (context.getType() !== 'http') return next.handle();

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    
    // High-precision clock start (Nanoseconds)
    const start = process.hrtime();

    const method = request.method || 'GET';
    const route = this.extractRoute(request);
    const tenantId = request.headers['x-tenant-id'] || 'zenith_kernel_default';

    /**
     * PRE-FLIGHT INSTRUMENTATION:
     * Increment active concurrent requests gauge.
     */
    this.telemetry.activeRequests.inc({ tenant_id: tenantId });
    
    // Global traffic counter
    this.telemetry.instanceTrafficVolume.inc({
      instance_id: process.env.HOSTNAME || 'zenith_node_primary',
      region: 'africa-north-1',
      cluster_zone: 'laghouat-01'
    });

    let isRecorded = false;

    return next.handle().pipe(
      tap(() => {
        /**
         * SUCCESS_PATH_OBSERVATION:
         * Captured on successful response resolution.
         */
        this.recordLatency(start, { 
          method, 
          route, 
          tenant_id: tenantId, 
          status_code: response.statusCode?.toString() || '200' 
        });
        isRecorded = true;
      }),
      catchError((error) => {
        /**
         * ANOMALY_OBSERVATION:
         * Captures telemetry even during failure states (Exception Filters).
         */
        const status = error instanceof HttpException ? error.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
        if (!isRecorded) {
          this.recordLatency(start, { 
            method, 
            route, 
            tenant_id: tenantId, 
            status_code: status.toString() 
          });
          isRecorded = true;
        }
        return throwError(() => error);
      }),
      finalize(() => {
        /**
         * CLEANUP:
         * Decrement concurrency gauge on lifecycle completion.
         */
        this.telemetry.activeRequests.dec({ tenant_id: tenantId });
      }),
    );
  }

  /**
   * @method extractRoute
   * @description Standardizes URL paths to maintain high-quality Prometheus label cardinality.
   */
  private extractRoute(request: any): string {
    // Uses the registered path (e.g., /api/users/:id) instead of raw URL (/api/users/1)
    const path = request.route?.path || request.url.split('?')[0];
    return path || 'unmapped_context';
  }

  /**
   * @method recordLatency
   * @description Computes delta time and dispatches to Summary & Histogram registries.
   * This is the core logic requested for Dual-Metric dispatch.
   */
  private recordLatency(start: [number, number], labels: any) {
    try {
      const diff = process.hrtime(start);
      const durationSeconds = diff[0] + diff[1] / 1e9;

      // Label Validation Gate
      const validatedLabels = {
        method: labels.method || 'GET',
        route: labels.route || 'unmapped',
        status_code: labels.status_code || '200',
        tenant_id: labels.tenant_id || 'system'
      };

      /**
       * DUAL-METRIC DISPATCH:
       * 1. Summary: Provides real-time P95/P99 quantiles.
       * 2. Histogram: Provides bucketed data for heatmap distribution analysis.
       */
      this.telemetry.httpLatency.observe(validatedLabels, durationSeconds);
      this.telemetry.httpDuration.observe(validatedLabels, durationSeconds);
      
      // Forensic debugging in development environments
      if (process.env.NODE_ENV !== 'production') {
        this.logger.debug(
          `[TELEMETRY_SYNC] ${validatedLabels.method} ${validatedLabels.route} | ` +
          `Status: ${validatedLabels.status_code} | Latency: ${durationSeconds.toFixed(4)}s`
        );
      }
    } catch (err) {
      this.logger.error(`[TELEMETRY_FAILURE] Dispatch engine error: ${err.message}`);
    }
  }
}