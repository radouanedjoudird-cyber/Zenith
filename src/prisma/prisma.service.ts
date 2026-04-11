import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';

/**
 * ZENITH SECURE PRISMA ENGINE - DATA PERSISTENCE LAYER v2.8
 * ---------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * ARCHITECTURAL STRATEGY:
 * 1. PERSISTENCE_LIFECYCLE: Graceful shutdown to prevent "Zombie Connections" in Neon/Serverless.
 * 2. PERFORMANCE_TELEMETRY: Real-time RTT tracking with bottleneck detection (>100ms).
 * 3. SECURITY_SHIELDING: Log sanitization to prevent Schema Leakage in production.
 * 4. INFRASTRUCTURE: Optimized for connection pooling and high-concurrency workloads.
 */
@Injectable()
export class PrismaService
  extends PrismaClient<Prisma.PrismaClientOptions, 'query' | 'error' | 'warn'>
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger('Zenith-Prisma-Engine');

  /**
   * CONSTRUCTOR CONFIGURATION
   * --------------------------
   * Standardizes the ORM behavior based on the execution context.
   */
  constructor() {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'warn' },
      ],
      // Error masking: 'pretty' formatting for local debugging, 'colorless' for logs parsing.
      errorFormat: process.env.NODE_ENV === 'development' ? 'pretty' : 'colorless',
    });
  }

  /**
   * INITIALIZATION PROTOCOL
   * -----------------------
   * Handshake with Neon Cluster. Implements "Fail-Fast" to avoid unstable application states.
   */
  async onModuleInit() {
    try {
      await this.$connect();
      this.logger.log('✅ [INFRA] Stable connection established with Data Registry.');

      // Initialize real-time auditing and performance monitoring
      this.bindTelemetryEvents();
      
    } catch (error) {
      this.handleCriticalFailure(error);
    }
  }

  /**
   * TELEMETRY BINDING ENGINE
   * -------------------------
   * Logic: Monitors query execution times and applies security filters.
   */
  private bindTelemetryEvents() {
    const isDev = process.env.NODE_ENV === 'development';

    /**
     * PERFORMANCE AUDITING:
     * High-speed logging. Identifies slow SQL queries that could impact RTT on HP-ProBook.
     */
    this.$on('query', (e: Prisma.QueryEvent) => {
      if (isDev) {
        if (e.duration > 100) {
          this.logger.warn(`🐢 [SLOW QUERY] ${e.duration}ms | Target: ${e.target} | SQL: ${e.query}`);
        } else {
          this.logger.debug(`⚡ [QUERY] ${e.duration}ms`);
        }
      }
    });

    /**
     * WARNING CAPTURE:
     * Preemptively identify potential indexing or connection issues.
     */
    this.$on('warn', (e: Prisma.LogEvent) => {
      this.logger.warn(`⚠️ [PRISMA WARN] ${e.message}`);
    });

    /**
     * SECURITY SHIELD: PRODUCTION SANITIZATION
     * Critical: Internal errors must NEVER be exposed in production logs
     * to prevent attackers from reverse-engineering the schema.
     */
    this.$on('error', (e: Prisma.LogEvent) => {
      if (isDev) {
        this.logger.error(`❌ [PRISMA ERROR] ${e.message}`);
      } else {
        // PRODUCTION: Generic reference for forensic team tracking.
        this.logger.error(`🚨 [CRITICAL DB ERROR] Internal Registry Operation Failed. [REF: ${Date.now()}]`);
      }
    });
  }

  /**
   * CRITICAL FAILURE HANDLER
   * -------------------------
   * Terminates process on handshake failure to prevent 'Zombie' nodes.
   */
  private handleCriticalFailure(error: any) {
    this.logger.error('☣️ [PANIC] Database handshake failed. System ignition aborted.');
    if (process.env.NODE_ENV === 'development') {
      this.logger.error(`Technical Detail: ${error.message}`);
    }
    process.exit(1);
  }

  /**
   * GRACEFUL DISCONNECTION
   * -----------------------
   * Essential for Serverless platforms (Neon) to prevent pool exhaustion.
   */
  async onModuleDestroy() {
    try {
      await this.$disconnect();
      this.logger.warn('🔌 [INFRA] Data pool released. Cleanup sequence complete.');
    } catch (error) {
      this.logger.error(`❌ [DISCONNECT ERROR] Forceful cleanup failed: ${error.message}`);
    }
  }
}