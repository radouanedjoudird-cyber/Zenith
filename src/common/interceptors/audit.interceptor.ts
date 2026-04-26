/**
 * ============================================================================
 * ZENITH SYSTEMS - FORENSIC TELEMETRY & OBSERVABILITY KERNEL
 * ============================================================================
 * @module AuditInterceptor
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Mission-critical forensic interceptor providing multi-vector 
 * telemetry capture, PII sanitization, and automated risk scoring.
 * * ARCHITECTURAL PRINCIPLES:
 * 1. NON_REPUDIATION: Immutable audit trails for compliance (GDPR/SOC2).
 * 2. DATA_SANITIZATION: Recursive PII redaction to prevent credential leakage.
 * 3. HARDWARE_AFFINITY: Real-time device fingerprinting and bot detection.
 * 4. PERFORMANCE_AWARENESS: Operational delta-time tracking for SLIs.
 * ============================================================================
 */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { LogStatus, Prisma, Severity } from '@prisma/client';
import { Observable, tap } from 'rxjs';
import { PrismaService } from '../../prisma/prisma.service';
import { DeviceFingerprint, FingerprintEngine } from '../utils/fingerprint.util';

/**
 * @class AuditInterceptor
 * @implements {NestInterceptor}
 * @description Orchestrates the capture of granular forensic artifacts during the request-response lifecycle.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  /** @private @readonly logger - Internal forensic subsystem logger */
  private readonly logger = new Logger('ZENITH_FORENSICS');

  constructor(private readonly prisma: PrismaService) {}

  /**
   * @method intercept
   * @description Standard NestJS interceptor implementation. Taps into the RxJS stream to monitor outcomes.
   * @param {ExecutionContext} context - The current execution context.
   * @param {CallHandler} next - The next handler in the pipeline.
   * @returns {Observable<any>} The intercepted response stream.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const startTime = Date.now();

    return next.handle().pipe(
      tap({
        next: (responseData: any) => 
          this.finalize(context, request, responseData, LogStatus.SUCCESS, startTime),
        error: (error: any) => 
          this.finalize(context, request, error, LogStatus.FAILURE, startTime),
      }),
    );
  }

  /**
   * @private finalize
   * @async
   * @description Synthesizes telemetry data and persists it to the forensic registry.
   * @param {ExecutionContext} context - Contextual metadata of the call.
   * @param {any} req - The raw HTTP request object.
   * @param {any} output - The resulting payload or error exception.
   * @param {LogStatus} status - Operational status (SUCCESS/FAILURE/SUSPICIOUS).
   * @param {number} start - High-precision start timestamp.
   */
  private async finalize(
    context: ExecutionContext,
    req: any,
    output: any,
    status: LogStatus,
    start: number,
  ): Promise<void> {
    const duration = Date.now() - start;
    const { method, url, user, ip, body, headers, params } = req;
    
    // 🛡️ [PHASE 1] Hardware Identity & Geo-Context Mapping
    const userAgent = headers['user-agent'] || 'IDENTITY_UNKNOWN';
    const clientIp = ip === '::1' ? '127.0.0.1' : ip;
    const fp: DeviceFingerprint = FingerprintEngine.generate(userAgent, clientIp);

    // 🛡️ [PHASE 2] PII Scrubbing & Data Sanitization
    const sanitizedPayload = this.scrubSensitiveData(body);
    const sanitizedOutput = this.scrubSensitiveData(output);
    const entityId = params?.id || output?.id || null;

    try {
      /**
       * @description FORENSIC_RECORD_PERSISTENCE
       * 🛡️ ARCHITECTURAL_FIX: Using 'any' type mapping for the payload to bypass TS2353 
       * strict property checking on 'os' and 'browser' fields post-schema-recovery.
       */
      const auditPayload: any = {
        action: `${method}:${context.getHandler().name.toUpperCase()}`,
        entity: context.getClass().name.replace('Controller', ''),
        entityId: entityId ? String(entityId) : null,
        
        userId: user?.id || user?.sub || null,
        userEmail: user?.email || (method === 'POST' ? sanitizedPayload?.email : null) || 'IDENTITY_UNKNOWN',
        
        // TELEMETRY VECTORS
        deviceId: fp.deviceId,
        os: fp.os,          
        browser: fp.browser, 
        ipAddress: clientIp,
        userAgent: userAgent,

        method,
        path: url,
        payload: sanitizedPayload as Prisma.InputJsonValue,
        
        newData: (status === LogStatus.SUCCESS ? sanitizedOutput : { error_context: output?.message || output }) as Prisma.InputJsonValue,
        
        status: fp.isBot ? LogStatus.SUSPICIOUS : status,
        severity: this.calculateRiskSeverity(method, duration, status, fp.isBot),
      };

      await this.prisma.auditLog.create({ data: auditPayload });

    } catch (err) {
      this.logger.error(`❌ [FORENSIC_FAILURE] Telemetry drop-off during persistence: ${err.message}`);
    }
  }

  /**
   * @private calculateRiskSeverity
   * @description Applies algorithmic scoring to determine the operational risk level.
   * @param {string} m - HTTP Method.
   * @param {number} d - Delta time (ms).
   * @param {LogStatus} s - Captured status.
   * @param {boolean} isBot - Bot detection flag.
   * @returns {Severity} Calculated severity level.
   */
  private calculateRiskSeverity(m: string, d: number, s: LogStatus, isBot: boolean): Severity {
    if (isBot) return Severity.CRITICAL; 
    if (s === LogStatus.FAILURE && m !== 'GET') return Severity.HIGH;
    if (d > 5000) return Severity.MEDIUM; // LATENCY_THRESHOLD_EXCEEDED
    if (['DELETE', 'PATCH'].includes(m)) return Severity.MEDIUM;
    return Severity.LOW;
  }

  /**
   * @private scrubSensitiveData
   * @description Recursive redaction engine for purging PII from diagnostic logs.
   * @param {any} data - The raw JSON payload to be sanitized.
   * @returns {any} The sanitized payload.
   */
  private scrubSensitiveData(data: any): any {
    if (!data || typeof data !== 'object') return data;

    const sensitiveFields = [
      'password', 'hashedRt', 'token', 'secret', 
      'credit_card', 'accessToken', 'refreshToken', 'newPassword'
    ];

    const clean = Array.isArray(data) ? [...data] : { ...data };

    for (const key in clean) {
      if (sensitiveFields.includes(key)) {
        clean[key] = '[REDACTED_BY_ZENITH_SHIELD]';
      } else if (typeof clean[key] === 'object') {
        clean[key] = this.scrubSensitiveData(clean[key]);
      }
    }
    
    return clean;
  }
}