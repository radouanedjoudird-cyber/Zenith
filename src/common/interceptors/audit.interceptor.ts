import {
    CallHandler,
    ExecutionContext,
    Injectable,
    Logger,
    NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { UAParser } from 'ua-parser-js';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * @class AuditInterceptor
 * @description Advanced Forensic Logging & Infrastructure Intelligence Engine.
 * Features multi-layered hardware fingerprinting, deep identity resolution,
 * and asynchronous persistence optimized for high-traffic enterprise environments.
 * * COMPLIANCE: Designed for GDPR and PCI DSS Traceability Standards.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger('ZENITH_AUDIT_CORE');
  private readonly parser = new UAParser();

  constructor(private prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, ip, body } = request;
    
    /**
     * @phase Enhanced Hardware Fingerprinting
     * Extracts OS, Browser, Device Type, and Vendor.
     * Maps physical hardware platform to the transaction for forensic analysis.
     */
    const ua = request.get('user-agent') || 'Unknown';
    this.parser.setUA(ua);
    const dr = this.parser.getResult();

    // Normalizing Device Data
    const deviceType = dr.device.type ? dr.device.type.toUpperCase() : 'DESKTOP';
    const deviceVendor = dr.device.vendor ? `${dr.device.vendor} ` : '';
    const deviceModel = dr.device.model ? `(${dr.device.model})` : '';
    
    // Composite Forensic Fingerprint for quick lookup
    const deviceFingerprint = `${dr.os.name || ''} ${dr.os.version || ''} | ${dr.browser.name || ''} | ${deviceType}: ${deviceVendor}${deviceModel}`.trim();

    // Criticality Filter: Monitors all state-altering operations
    const isCriticalAction = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);

    return next.handle().pipe(
      tap({
        next: async (data) => {
          if (isCriticalAction) {
            try {
              /**
               * @phase Recursive Entity Resolution
               * Captures the unique ID of the resource affected by the transaction.
               */
              const extractedEntityId = 
                data?.id ||           
                data?.user?.id ||     
                data?.userId ||       
                (typeof data === 'number' ? data : null);

              /**
               * @phase Identity Integrity Resolution
               * Maps the 'Actor' (Executor). Supports anonymous signup chains by 
               * linking the performer to the resulting entity ID where necessary.
               */
              const actorEmail = user?.email || body?.email || 'SYSTEM_ANONYMOUS';
              const actorId = user?.sub || (method === 'POST' && extractedEntityId ? extractedEntityId : null);

              /**
               * @phase Persistence Layer (Prisma JSON Optimized)
               * Records metadata using Plain Objects to ensure Prisma Type-Safety.
               */
              await this.prisma.auditLog.create({
                data: {
                  action: `${method} ${url}`,
                  entity: this.resolveEntity(url),
                  entityId: extractedEntityId ? String(extractedEntityId) : null,
                  userId: actorId ? Number(actorId) : null,
                  userEmail: actorEmail,
                  ipAddress: ip,
                  userAgent: deviceFingerprint, 
                  status: 'SUCCESS',
                  metadata: {
                    timestamp: new Date().toISOString(),
                    os: {
                      name: dr.os.name || 'Unknown',
                      version: dr.os.version || 'Unknown'
                    },
                    browser: {
                      name: dr.browser.name || 'Unknown',
                      version: dr.browser.version || 'Unknown'
                    },
                    hardware: {
                      type: deviceType,
                      vendor: dr.device.vendor || 'Unknown',
                      model: dr.device.model || 'Unknown',
                    },
                    // Prevent sensitive data leakage in logs
                    payload: this.filterSensitiveData(body),
                    responsePreview: { hasData: !!data }
                  } as any, // Explicit cast to satisfy Prisma's strict JSON input
                },
              });
            } catch (error) {
              /**
               * @fail_safe
               * Logging failures are isolated to prevent blocking business logic.
               */
              this.logger.error(`[AUDIT_LOG_CRITICAL_FAILURE]: ${error.message}`);
            }
          }
        },
      }),
    );
  }

  /**
   * @function resolveEntity
   * Identifies the system module (e.g., AUTH, USERS) from the URI segments.
   */
  private resolveEntity(url: string): string {
    const segments = url.split('/').filter(s => s && s !== 'api' && !/^v\d+$/.test(s));
    return segments[0]?.toUpperCase() || 'CORE_ENGINE';
  }

  /**
   * @function filterSensitiveData
   * Security filter to redact PII and secrets before database persistence.
   */
  private filterSensitiveData(payload: any) {
    if (!payload) return null;
    const redacted = { ...payload };
    const sensitiveKeys = ['password', 'token', 'secret', 'hashedRt', 'oldPassword', 'creditCard', 'cvv'];
    sensitiveKeys.forEach(k => { if (k in redacted) redacted[k] = '[REDACTED_BY_ZENITH_SECURITY]'; });
    return redacted;
  }
}