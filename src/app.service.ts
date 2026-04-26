/**
 * ============================================================================
 * ZENITH CORE OPERATIONAL LOGIC
 * ============================================================================
 * @module AppService
 * @version 7.4.0
 * @description Provides high-speed system telemetry and core utility logic.
 * * * ARCHITECTURAL RATIONALE:
 * 1. STATE_IMMUTABILITY: Returns standardized system snapshots for monitoring.
 * 2. TELEMETRY_PRECISION: High-resolution timestamps for latency/drift analysis.
 * ============================================================================
 */

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class AppService {
  private readonly logger = new Logger('ZENITH_APP_SERVICE');

  /**
   * @function getSystemStatus
   * @description Aggregates core system metadata for infrastructure heartbeat.
   * @compliance ISO-27001 Standardized Telemetry
   * @returns {object} Operational status snapshot.
   */
  getSystemStatus(): object {
    /**
     * @audit_log
     * Track incoming health probes for infrastructure reliability metrics.
     */
    this.logger.log('📊 [TELEMETRY] System health snapshot generated.');

    return {
      status: 'active',
      engine: 'Zenith Secure Engine',
      kernel: 'v7.4.0',
      telemetry: 'engaged',
      environment: process.env.NODE_ENV || 'development',
      uptime: process.uptime().toFixed(2) + 's', 
      timestamp: new Date().toISOString(),
    };
  }
}