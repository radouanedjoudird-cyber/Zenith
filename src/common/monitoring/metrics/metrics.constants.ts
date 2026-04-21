/**
 * @fileoverview Metrics constants for Zenith Engine.
 * Essential for maintaining label consistency across Prometheus and Grafana.
 */

export const METRICS_NAMES = {
  HTTP_REQUEST_DURATION: 'zenith_http_request_duration_seconds',
  HTTP_ACTIVE_REQUESTS: 'zenith_http_active_requests',
};

/**
 * Global labels for multi-tenant isolation analysis.
 * Helps solve the "Noisy Neighbor" problem in the thesis.
 */
export const METRICS_LABELS = ['method', 'route', 'status_code', 'tenant_id'];