import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { LogStatus, Severity } from '@prisma/client';
import { tap } from 'rxjs/operators';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * ZENITH ADVANCED FORENSIC ENGINE - TELEMETRY v5.0
 * -----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @description Global interceptor for high-fidelity audit trail orchestration.
 * FEATURES:
 * 1. STATE_SNAPSHOT: Captures request payload and response metadata.
 * 2. PERFORMANCE_METRICS: Precise latency tracking.
 * 3. IDENTITY_CONTEXT: Seamless user and entity identification.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger('ZENITH_FORENSIC_ENGINE');

  constructor(private prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, ip, body, params } = request;
    const startTime = Date.now();

    return next.handle().pipe(
      tap({
        next: async (responseData) => {
          const latency = Date.now() - startTime;
          
          // Determine the targeted entity ID (e.g., from /users/:id)
          const entityId = params?.id || responseData?.id || null;

          await this.persistLog({
            context,
            method,
            path: url,
            user,
            ip,
            payload: body,
            responseData,
            latency,
            entityId,
          });
        },
        error: async (err) => {
          // Capturing Failed Attempts for Security Auditing
          await this.persistLog({
            context,
            method,
            path: url,
            user,
            ip,
            payload: body,
            status: LogStatus.FAILURE,
            latency: Date.now() - startTime,
            error: err.message,
          });
        },
      }),
    );
  }

  private async persistLog(data: any) {
    const { context, method, path, user, ip, payload, responseData, latency, entityId, status, error } = data;

    try {
      // 🛡️ SECURITY FILTER: Scrub sensitive data before logging
      const sanitizedPayload = { ...payload };
      if (sanitizedPayload.password) sanitizedPayload.password = '[REDACTED]';

      await this.prisma.auditLog.create({
        data: {
          action: `${method}_${context.getHandler().name.toUpperCase()}`,
          path,
          method,
          entity: context.getClass().name.replace('Controller', ''),
          entityId: entityId ? String(entityId) : null,
          
          userId: user?.id || null,
          userEmail: user?.email || payload?.email || 'Anonymous',
          
          payload: sanitizedPayload,
          // 🟢 Advanced Feature: Storing the resulting state
          newData: responseData ? this.sanitizeResponse(responseData) : (error ? { error } : null),
          
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: context.switchToHttp().getRequest().get('user-agent'),
          
          status: status || LogStatus.SUCCESS,
          severity: this.calculateSeverity(method, latency, status),
        },
      });
    } catch (err) {
      this.logger.error(`❌ [FORENSIC FAILURE] Could not persist audit trail: ${err.message}`);
    }
  }

  /**
   * SEVERITY MATRIX v5.0
   */
  private calculateSeverity(method: string, latency: number, status?: LogStatus): Severity {
    if (status === LogStatus.FAILURE || status === LogStatus.SUSPICIOUS) return Severity.HIGH;
    if (latency > 2000) return Severity.MEDIUM; // Performance warning
    if (['DELETE', 'PATCH', 'POST'].includes(method)) return Severity.MEDIUM;
    return Severity.LOW;
  }

  /**
   * SCRUBBER: Removes sensitive fields from response data before persistence
   */
  private sanitizeResponse(data: any) {
    if (typeof data !== 'object' || data === null) return data;
    const clean = { ...data };
    delete clean.password;
    delete clean.hashedRt;
    return clean;
  }
}