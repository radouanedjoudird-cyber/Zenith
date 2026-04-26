/**
 * ============================================================================
 * ZENITH SECURE KERNEL - TELEMETRY REGISTRY & ANALYTICS v7.4.0
 * ============================================================================
 * @module MonitoringService
 * @description Orchestrates high-fidelity metrics for predictive observability.
 * * ARCHITECTURAL STANDARDS:
 * 1. SLI_PRECISION: Implements Summary quantiles (0.95/0.99) for tail latency.
 * 2. DISTRIBUTION_ANALYSIS: Uses Histograms for heatmaps and SLO compliance.
 * 3. REGISTRY_CONSISTENCY: Enforces metric singleton pattern via prom-client.
 * ============================================================================
 */

import { Injectable } from '@nestjs/common';
import { Counter, Gauge, Histogram, Summary } from 'prom-client';

@Injectable()
export class MonitoringService {
  /**
   * @property httpLatency
   * @description P95/P99 Summary for real-time tail latency forensics.
   */
  public readonly httpLatency: Summary<string>;

  /**
   * @property httpDuration
   * @description Histogram for distribution analysis (Buckets: 100ms to 5s).
   */
  public readonly httpDuration: Histogram<string>;

  /**
   * @property instanceTrafficVolume
   * @description Global counter for total request volume across the cluster.
   */
  public readonly instanceTrafficVolume: Counter<string>;

  /**
   * @property activeRequests
   * @description Real-time Gauge for monitoring concurrent request saturation.
   */
  public readonly activeRequests: Gauge<string>;

  constructor() {
    // 1. Latency Summary (Quantiles)
    this.httpLatency = new Summary({
      name: 'zenith_http_latency_seconds',
      help: 'Granular Latency Quantiles for performance SLO tracking.',
      labelNames: ['method', 'route', 'status_code', 'tenant_id'],
      percentiles: [0.5, 0.9, 0.95, 0.99], // Expanded for better PFE analysis
      maxAgeSeconds: 600,
      ageBuckets: 5,
    });

    // 2. Latency Histogram (Buckets) - IDEAL FOR GRAFANA HEATMAPS
    this.httpDuration = new Histogram({
      name: 'zenith_http_duration_seconds',
      help: 'HTTP request duration distribution in buckets.',
      labelNames: ['method', 'route', 'status_code', 'tenant_id'],
      buckets: [0.05, 0.1, 0.3, 0.5, 1, 1.5, 2.5, 5], // Strategic buckets for stress testing
    });

    // 3. Traffic Volume Counter
    this.instanceTrafficVolume = new Counter({
      name: 'zenith_instance_traffic_total',
      help: 'Total request volume dispatched per instance.',
      labelNames: ['instance_id', 'region', 'cluster_zone'],
    });

    // 4. Concurrency Gauge
    this.activeRequests = new Gauge({
      name: 'zenith_http_active_requests',
      help: 'Current concurrent HTTP requests being processed.',
      labelNames: ['tenant_id'],
    });
  }
}