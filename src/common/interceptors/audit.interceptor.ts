import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { LogSeverity } from '@prisma/client'; // Import the new Enum
import * as os from 'os';
import { tap } from 'rxjs/operators';
import { PrismaService } from '../../prisma/prisma.service';

const UAParser = require('ua-parser-js');

/**
 * ZENITH FORENSIC ENGINE - TELEMETRY INTERCEPTOR v2.3
 * ---------------------------------------------------
 * STRATEGY: 
 * 1. ZERO-BLOCKING: Fire-and-forget database persistence for logs.
 * 2. HARDWARE OBSERVABILITY: Real-time HP-ProBook resource monitoring.
 * 3. ANOMALY DETECTION: Latency-based severity escalation.
 * 4. PII PROTECTION: Metadata capture without sensitive payload leaks.
 * * @author Radouane Djoudi
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger('Zenith-Forensic-Engine');

  constructor(private prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, ip, body } = request;
    const startTime = Date.now();
    
    // DEVICE FINGERPRINTING: Parsing User-Agent for detailed forensic auditing.
    const ua = new UAParser(request.get('user-agent')).getResult();

    return next.handle().pipe(
      tap({
        next: async (responseData) => {
          const latencyInMs = Date.now() - startTime;
          
          /**
           * TELEMETRY GATHERING:
           * Non-blocking resource calculation.
           */
          const totalMem = os.totalmem();
          const freeMem = os.freemem();
          const ramUsage = `${((1 - freeMem / totalMem) * 100).toFixed(2)}%`;
          const cpuLoad = os.loadavg()[0].toFixed(2);

          // ASYNC LOGGING: Using fire-and-forget to maintain high RTT performance.
          this.persistLog(
            context, method, url, user, ip, body, responseData, 
            latencyInMs, ramUsage, cpuLoad, ua
          );
        },
      }),
    );
  }

  /**
   * PERSISTENCE LOGIC:
   * Decoupled method for cleaner execution and error handling.
   */
  private async persistLog(
    context: ExecutionContext, method: string, url: string, user: any, 
    ip: string, body: any, responseData: any, latencyInMs: number,
    ramUsage: string, cpuLoad: string, ua: any
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          action: `${method} ${context.getHandler().name}`,
          entity: context.getClass().name,
          userId: user?.id || responseData?.id || null,
          userEmail: user?.email || body?.email || responseData?.email || 'System/Anonymous',
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: `${ua.browser.name || 'Unknown'} on ${ua.os.name || 'Unknown'}`,
          status: 'SUCCESS',
          // Performance Tuning: Using our improved severity matrix
          severity: this.calculateSeverity(method, url, latencyInMs),
          
          details: {
            performance: { 
              latency: `${latencyInMs}ms`, 
              server_cpu: `${cpuLoad}%`, 
              server_ram: ramUsage,
              process_id: process.pid 
            },
            fingerprint: { 
              arch: ua.cpu.architecture, 
              os_ver: ua.os.version, 
              device: ua.device.model || 'Workstation',
            },
            context: {
              path: url,
              controller: context.getClass().name,
              handler: context.getHandler().name,
            }
          },
        },
      });
    } catch (err) {
      this.logger.error(`❌ [FORENSIC FAILURE] Audit Trail persistence failed: ${err.message}`);
    }
  }

  /**
   * ADVANCED SEVERITY MATRIX:
   * Maps strictly to the LogSeverity Enum defined in schema.prisma.
   */
  private calculateSeverity(method: string, url: string, latency: number): LogSeverity {
    // 1. ANOMALY DETECTED: Latency > 1.5s is a critical performance issue.
    if (latency > 1500) return LogSeverity.CRITICAL;

    // 2. DESTRUCTIVE ACTIONS: Hard-coded security rule.
    if (method === 'DELETE' || url.includes('/admin/config')) return LogSeverity.SECURITY_ALERT;

    // 3. STATE CHANGES: Moderate monitoring.
    if (['PATCH', 'PUT', 'POST'].includes(method)) return LogSeverity.WARN;

    // 4. STANDARD FLOW.
    return LogSeverity.INFO;
  }
}