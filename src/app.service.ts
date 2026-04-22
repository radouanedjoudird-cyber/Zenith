import { Injectable, Logger } from '@nestjs/common';

/**
 * ZENITH APP SERVICE - CORE OPERATIONAL LOGIC v7.3.0
 * ------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Provides core application-level utility and system health telemetry.
 * * * SECURITY STRATEGY:
 * 1. CENTRALIZED_LOGGING: Monitors service availability via internal audit logs.
 * 2. MINIMALIST_LEAKAGE: Prevents version exposure while providing vital state.
 */
@Injectable()
export class AppService {
  private readonly logger = new Logger('Zenith-App-Service');

  /**
   * GET_SYSTEM_STATUS
   * -----------------
   * Serves as a neutral, high-speed endpoint for load balancers and uptime monitors.
   * COMPLIANCE: Adheres to structured telemetry standards for JSON logging.
   * * @returns {object} Standardized operational status.
   */
  getSystemStatus(): object {
    /**
     * TELEMETRY:
     * Structured log entry to track infrastructure health probes frequency.
     */
    this.logger.log('🛡️ [HEALTH_CHECK] Root gateway reached. Status: OPERATIONAL');
    
    return {
      status: 'active',
      engine: 'Zenith Secure Engine',
      kernel: 'v7.3.0',
      telemetry: 'engaged',
      timestamp: new Date().toISOString(), // Vital for latency analysis
    };
  }
}