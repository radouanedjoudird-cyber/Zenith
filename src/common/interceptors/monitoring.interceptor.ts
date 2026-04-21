/**
 * @class MonitoringInterceptor
 * @description Global interceptor for high-fidelity telemetry.
 * Captures latency and active request signals for every HTTP lifecycle.
 */

import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { Gauge, Histogram } from 'prom-client';
import { Observable } from 'rxjs';
import { finalize, tap } from 'rxjs/operators';
import { METRICS_NAMES } from '../monitoring/metrics/metrics.constants';

@Injectable()
export class MonitoringInterceptor implements NestInterceptor {
  constructor(
    @InjectMetric(METRICS_NAMES.HTTP_REQUEST_DURATION) private readonly latencyHisto: Histogram<string>,
    @InjectMetric(METRICS_NAMES.HTTP_ACTIVE_REQUESTS) private readonly activeRequestsGauge: Gauge<string>,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') return next.handle();

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    
    // Multi-tenant context extraction
    const tenantId = request.headers['x-tenant-id']?.toString() || 'system_default';
    const path = request.route?.path || request.url;

    // Start timer for P99 analysis
    const stopTimer = this.latencyHisto.startTimer({ 
      method: request.method, 
      route: path, 
      tenant_id: tenantId 
    });

    // Notify KEDA of real-time load
    this.activeRequestsGauge.inc({ tenant_id: tenantId });

    return next.handle().pipe(
      tap({
        next: () => stopTimer({ status_code: response.statusCode }),
        error: (err) => stopTimer({ status_code: err.status || 500 }),
      }),
      finalize(() => {
        // Decrement when request finishes or fails
        this.activeRequestsGauge.dec({ tenant_id: tenantId });
      }),
    );
  }
}