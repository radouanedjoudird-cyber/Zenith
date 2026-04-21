/**
 * ============================================================================
 * ZENITH CORE - HIGH-FIDELITY MONITORING INTERCEPTOR
 * ============================================================================
 * @class MonitoringInterceptor
 * @description Automated Telemetry Collection Engine using AOP (Aspect-Oriented Programming).
 * * DESIGN RATIONALE (ENTERPRISE GRADE):
 * 1. ATOMICITY: Ensures Gauge increments are always balanced with decrements using 'finalize'.
 * 2. DIMENSIONALITY: Rich labeling (method, route, status, tenant) for deep-dive PromQL queries.
 * 3. ERROR_CLASSIFICATION: Maps HTTP exceptions to error counters before they are sanitized.
 * 4. PERFORMANCE: Minimal overhead by using direct 'prom-client' references.
 * * @author Radouane Djoudi
 * @version 1.0.0
 * ============================================================================
 */

import {
    CallHandler,
    ExecutionContext,
    HttpException,
    HttpStatus,
    Injectable,
    NestInterceptor,
} from '@nestjs/common';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { Counter, Gauge, Histogram } from 'prom-client';
import { Observable, throwError } from 'rxjs';
import { catchError, finalize, tap } from 'rxjs/operators';
import { METRICS_NAMES } from '../metrics/metrics.constants';

@Injectable()
export class MonitoringInterceptor implements NestInterceptor {
  constructor(
    @InjectMetric(METRICS_NAMES.HTTP_REQUEST_DURATION)
    private readonly responseTime: Histogram<string>,

    @InjectMetric(METRICS_NAMES.HTTP_ACTIVE_REQUESTS)
    private readonly activeRequests: Gauge<string>,

    /**
     * @metric zenith_api_errors_total
     * Custom Counter injected to track failure rates across the cluster.
     */
    @InjectMetric('zenith_api_errors_total')
    private readonly errorCounter: Counter<string>,
  ) {}

  /**
   * @method intercept
   * @description Wraps the request/response lifecycle to inject telemetry logic.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 1. Context Validation: Ensure we only monitor HTTP traffic (Bypass WebSockets/Microservices if needed)
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    
    /**
     * EXTRACT_METADATA:
     * Extracting 'tenant_id' for Multi-tenant resource accounting.
     * Fallback to 'system_kernel' for internal or unauthenticated probes.
     */
    const tenantId = request.headers['x-tenant-id'] || 'system_kernel';

    // 2. INITIALIZATION: Start the high-resolution timer and increment occupancy gauge
    const stopTimer = this.responseTime.startTimer({ 
      method, 
      route: url, 
      tenant_id: tenantId 
    });
    
    this.activeRequests.inc({ tenant_id: tenantId });

    return next.handle().pipe(
      /**
       * SUCCESS_PATH:
       * Capturing metrics for 2xx and 3xx responses.
       */
      tap(() => {
        const response = context.switchToHttp().getResponse();
        stopTimer({ status_code: response.statusCode.toString() });
      }),

      /**
       * EXCEPTION_PATH:
       * Capturing metrics for 4xx and 5xx errors.
       * Logic: Extracts status from HttpException or defaults to 500 (Internal Server Error).
       */
      catchError((error) => {
        const statusCode = error instanceof HttpException 
          ? error.getStatus() 
          : HttpStatus.INTERNAL_SERVER_ERROR;

        this.errorCounter.inc({ 
          method, 
          route: url, 
          error_code: statusCode.toString(), 
          tenant_id: tenantId 
        });

        stopTimer({ status_code: statusCode.toString() });
        return throwError(() => error);
      }),

      /**
       * FINALIZE:
       * Guaranteed execution (like 'finally' in JS).
       * Ensures 'active_requests' gauge is decremented even if the stream is cancelled or crashes.
       */
      finalize(() => {
        this.activeRequests.dec({ tenant_id: tenantId });
      }),
    );
  }
}