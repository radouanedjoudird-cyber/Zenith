/**
 * ============================================================================
 * ZENITH CORE INFRASTRUCTURE - TELEMETRY PROVIDERS
 * ============================================================================
 * @module TelemetryProviders
 * @description Enterprise-grade Prometheus metric definitions for Zenith Engine.
 * * ARCHITECTURAL DESIGN (BIG TECH STANDARDS):
 * 1. SLI_COMPLIANCE: Aligned with "Four Golden Signals" (Latency, Traffic, Errors, Saturation).
 * 2. QUANTILE_ACCURACY: Optimized buckets for P95/P99 latency analysis in high-concurrency environments.
 * 3. TENANCY_ISOLATION: Mandatory 'tenant_id' label for per-client resource accounting (SaaS Ready).
 * 4. KEDA_OPTIMIZED: Gauge metrics structured for Horizontal Pod Autoscaling (HPA) via KEDA.
 * * @author Radouane Djoudi
 * @version 14.0.0
 * ============================================================================
 */

import { makeCounterProvider, makeGaugeProvider, makeHistogramProvider } from '@willsoto/nestjs-prometheus';
import { METRICS_NAMES } from './metrics.constants';

export const prometheusProviders = [
  /**
   * @provider HTTP_REQUEST_DURATION (Histogram)
   * @description Measures the request-response lifecycle latency distribution.
   * * STRATEGY: Used for identifying performance bottlenecks and SLO breaches.
   * * BUCKET_CHOICE: Fine-grained between 50ms and 500ms to capture micro-fluctuations 
   * in API performance before they escalate to system-level degradation.
   */
  makeHistogramProvider({
    name: METRICS_NAMES.HTTP_REQUEST_DURATION,
    help: 'Total latency distribution of HTTP requests (Golden Signal: Latency)',
    labelNames: ['method', 'route', 'status_code', 'tenant_id'],
    /**
     * BUCKETS RATIONALE: 
     * [0.005, 0.01] -> Internal Microservices (Fast)
     * [0.025 to 0.5] -> Standard API Response (Operational)
     * [1 to 10] -> Long-running jobs/Heavy DB queries (Critical)
     */
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10], 
  }),

  /**
   * @provider HTTP_ACTIVE_REQUESTS (Gauge)
   * @description Tracks real-time concurrent processing occupancy.
   * * STRATEGY: Primary telemetry source for KEDA (Kubernetes Event-driven Autoscaling).
   * * PURPOSE: Measures 'Saturation' to trigger vertical or horizontal scaling.
   */
  makeGaugeProvider({
    name: METRICS_NAMES.HTTP_ACTIVE_REQUESTS,
    help: 'In-flight requests currently being processed (Golden Signal: Saturation)',
    labelNames: ['tenant_id', 'pod_id'], // Pod_id added for granular cluster visibility
  }),

  /**
   * @provider API_ERROR_RATE (Counter)
   * @description Tracks cumulative system failures and non-2xx responses.
   * * STRATEGY: Critical for automated rollback and alerting systems (PagerDuty/Sentry).
   * * PURPOSE: Measures 'Errors' Golden Signal.
   */
  makeCounterProvider({
    name: 'zenith_api_errors_total',
    help: 'Cumulative count of failed requests (Golden Signal: Errors)',
    labelNames: ['method', 'route', 'error_code', 'tenant_id'],
  }),
];