import { CallHandler, ExecutionContext, Injectable, Logger, NestInterceptor } from '@nestjs/common';
import * as os from 'os';
import { tap } from 'rxjs/operators';
import { PrismaService } from '../../prisma/prisma.service';

const UAParser = require('ua-parser-js');

/**
 * ZENITH AUDIT & TELEMETRY INTERCEPTOR
 * ------------------------------------
 * PURPOSE: Forensic logging, Performance Monitoring & Resource Auditing.
 * METRICS: Captures Latency, RAM Usage, and CPU Load (HP-ProBook Telemetry).
 * PERFORMANCE: Uses Async non-blocking persistence to maintain high throughput.
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly logger = new Logger('ZenithAuditEngine');

  constructor(private prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, ip, body } = request;
    const startTime = Date.now();
    const ua = new UAParser(request.get('user-agent')).getResult();

    return next.handle().pipe(
      tap({
        next: async (responseData) => {
          const latency = `${Date.now() - startTime}ms`;
          
          // INFRASTRUCTURE TELEMETRY: HP ProBook Metrics
          const ramUsage = `${((1 - os.freemem() / os.totalmem()) * 100).toFixed(2)}%`;
          const cpuLoad = os.loadavg()[0].toFixed(2);

          // DATA PERSISTENCE: Safe background logging
          this.prisma.auditLog.create({
            data: {
              action: `${method} ${context.getHandler().name}`,
              entity: context.getClass().name,
              userId: user?.sub || responseData?.id || null,
              userEmail: user?.email || body?.email || responseData?.email || 'Anonymous',
              ipAddress: ip === '::1' ? '127.0.0.1' : ip,
              userAgent: `${ua.browser.name} on ${ua.os.name}`,
              status: 'SUCCESS',
              severity: this.calculateSeverity(method, url),
              details: {
                performance: { latency, server_cpu: `${cpuLoad}%`, server_ram: ramUsage },
                fingerprint: { arch: ua.cpu.architecture, os_ver: ua.os.version, device: ua.device.model || 'PC' }
              },
            },
          }).catch(err => this.logger.error(`Forensic log failure: ${err.message}`));
        },
      }),
    );
  }

  private calculateSeverity(method: string, url: string): string {
    if (method === 'DELETE' || url.includes('admin')) return 'CRITICAL';
    if (['PATCH', 'PUT'].includes(method)) return 'WARN';
    return 'INFO';
  }
}