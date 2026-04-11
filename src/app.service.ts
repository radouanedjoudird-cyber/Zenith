import { Injectable, Logger } from '@nestjs/common';

/**
 * ZENITH APP SERVICE - CORE OPERATIONAL LOGIC v1.2
 * ------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Provides core application-level utility and system health telemetry.
 * * * SECURITY STRATEGY:
 * 1. CENTRALIZED_LOGGING: Monitors service availability via internal audit logs.
 * 2. MINIMALIST_LEAKAGE: Prevents version/infrastructure exposure in public strings.
 */
@Injectable()
export class AppService {
  private readonly logger = new Logger('Zenith-App-Service');

  /**
   * SYSTEM HEALTH CHECK (GET_HELLO)
   * -------------------------------
   * Serves as a neutral, high-speed endpoint for load balancers and uptime monitors.
   * COMPLIANCE: Adheres to 'Security-by-Obscurity' by returning non-descriptive status.
   * * @returns {string} Operational status message.
   */
  getHello(): string {
    /**
     * TELEMETRY:
     * This log entry is crucial for forensic analysis if the system is being
     * probed by scanners. It tracks frequency and ingress at the root level.
     */
    this.logger.log('🛡️ [HEALTH_CHECK] Root gateway reached. Status: OPERATIONAL');
    
    return 'Zenith Cloud API: Operational';
  }
}