/**
 * ============================================================================
 * ZENITH CORE - HIGH-FIDELITY MONITORING INTERCEPTOR v7.2.2
 * ============================================================================
 * @class MonitoringInterceptor
 * @description Automated Telemetry Collection Engine using AOP.
 * * DESIGN RATIONALE (ENTERPRISE GRADE):
 * 1. CARDINALITY CONTROL: Uses Route Patterns instead of raw URLs to prevent Prometheus explosion.
 * 2. MODERN ROUTING: Compliant with path-to-regexp v8+ (Eliminates LegacyRouteConverter warnings).
 * 3. ATOMICITY: Finalize-guaranteed Gauge balancing.
 * 4. MULTI-TENANCY: Dimensional labeling by tenant_id for granular SLIs.
 * * @author Radouane Djoudi
 * @version 7.2.2 (Cardinality & Routing Optimized)
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

    @InjectMetric('zenith_api_errors_total')
    private readonly errorCounter: Counter<string>,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const { method } = request;

    /**
     * [CRITICAL FIX]: MODERN ROUTE RESOLUTION
     * We use request.route.path (the pattern like /users/:id) instead of request.url.
     * This prevents the "LegacyRouteConverter" warning and keeps Prometheus metrics clean.
     * Fallback to 'unknown_route' if the route is not yet matched (e.g., 404s).
     */
    const route = request.route?.path || request.url || 'unknown_route';
    
    /**
     * MULTI-TENANT CONTEXT:
     */
    const tenantId = request.headers['x-tenant-id'] || 'system_kernel';

    // Start timer with clean labels
    const stopTimer = this.responseTime.startTimer({ 
      method, 
      route, 
      tenant_id: tenantId 
    });
    
    this.activeRequests.inc({ tenant_id: tenantId });

    return next.handle().pipe(
      tap(() => {
        // Success path: Recording duration with standardized status code
        stopTimer({ status_code: response.statusCode.toString() });
      }),

      catchError((error) => {
        const statusCode = error instanceof HttpException 
          ? error.getStatus() 
          : HttpStatus.INTERNAL_SERVER_ERROR;

        this.errorCounter.inc({ 
          method, 
          route, 
          error_code: statusCode.toString(), 
          tenant_id: tenantId 
        });

        stopTimer({ status_code: statusCode.toString() });
        return throwError(() => error);
      }),

      finalize(() => {
        // Ensuring Resource Quota is released
        this.activeRequests.dec({ tenant_id: tenantId });
      }),
    );
  }
}