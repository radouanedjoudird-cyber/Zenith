/**
 * @fileoverview Global Forensic Audit Interceptor for Zenith Engine.
 * Implements high-fidelity telemetry, hardware fingerprinting, and PII masking.
 * Inspired by Google's Dapper and Netflix's observability patterns.
 * * @author Radouane Djoudi
 * @version 6.0.0
 */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { LogStatus, Severity } from '@prisma/client';
import { Observable, tap } from 'rxjs';
import { PrismaService } from '../../prisma/prisma.service';
import { DeviceFingerprint, FingerprintEngine } from '../utils/fingerprint.util';

/**
 * AuditInterceptor captures full-stack telemetry for every transaction.
 * Features automated Device ID generation and dynamic severity scaling.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger('ZENITH_FORENSICS');

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Orchestrates the interception of incoming HTTP requests.
   * Logs device-aware metadata and mutation snapshots.
   * * @param context - The execution context of the request.
   * @param next - The call handler for the next step in the pipeline.
   * @returns {Observable<any>} The response stream.
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const http = context.switchToHttp();
    const request = http.getRequest();
    const startTime = Date.now();

    return next.handle().pipe(
      tap({
        next: (responseData) => this.finalize(context, request, responseData, LogStatus.SUCCESS, startTime),
        error: (error) => this.finalize(context, request, error, LogStatus.FAILURE, startTime),
      }),
    );
  }

  /**
   * Finalizes the telemetry record and persists it to the Data Registry.
   * @private
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
    
    // 🛡️ [STEP 1] Generate Enterprise Hardware Fingerprint
    const fp: DeviceFingerprint = FingerprintEngine.generate(headers['user-agent'] || '', ip);

    // 🛡️ [STEP 2] PII Scrubbing (Personally Identifiable Information)
    const sanitizedPayload = this.scrubSensitiveData(body);
    const entityId = params?.id || output?.id || null;

    try {
      await this.prisma.auditLog.create({
        data: {
          action: `${method}_${context.getHandler().name.toUpperCase()}`,
          entity: context.getClass().name.replace('Controller', ''),
          entityId: entityId ? String(entityId) : null,
          
          userId: user?.id || null,
          userEmail: user?.email || sanitizedPayload?.email || 'Anonymous',
          
          // 📡 [STEP 3] Hardware & Network Mapping
          deviceId: fp.deviceId,
          os: fp.os,
          browser: fp.browser,
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: headers['user-agent'],

          method,
          path: url,
          payload: sanitizedPayload,
          newData: status === LogStatus.SUCCESS ? this.scrubSensitiveData(output) : { error: output.message },
          
          status: fp.isBot ? LogStatus.SUSPICIOUS : status,
          severity: this.calculateSeverity(method, duration, status, fp.isBot),
        },
      });
    } catch (err) {
      this.logger.error(`❌ [FORENSIC FAILURE] Persistence Error: ${err.message}`);
    }
  }

  /**
   * Advanced Severity Matrix based on operational risk factors.
   * @private
   */
  private calculateSeverity(m: string, d: number, s: LogStatus, bot: boolean): Severity {
    if (bot || s === LogStatus.FAILURE && m !== 'GET') return Severity.HIGH;
    if (d > 2000 || ['DELETE', 'POST', 'PATCH'].includes(m)) return Severity.MEDIUM;
    return Severity.LOW;
  }

  /**
   * High-Performance Scrubber to prevent credential leakage in logs.
   * @private
   */
  private scrubSensitiveData(data: any): any {
    if (!data || typeof data !== 'object') return data;
    const sensitiveFields = ['password', 'hashedRt', 'token', 'secret', 'credit_card'];
    const clean = { ...data };
    
    sensitiveFields.forEach(field => {
      if (field in clean) clean[field] = '[REDACTED_FOR_SECURITY]';
    });
    
    return clean;
  }
}