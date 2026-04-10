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
 * STRATEGY:
 * 1. PERSISTENCE LIFECYCLE: Implementation of Graceful Shutdown to prevent "Zombie Connections" in Cloud/Neon environments.
 * 2. PERFORMANCE TELEMETRY: Real-time RTT (Round-Trip Time) tracking with automated bottleneck detection (>100ms).
 * 3. SECURITY SHIELDING: Advanced log sanitization to prevent Schema Leakage and PII exposure in Production logs.
 * 4. INFRASTRUCTURE: Optimized for Neon Serverless pooling logic and Local Dev performance on HP-ProBook.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
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
   * Standardizes the ORM behavior based on the execution context (DEV vs PROD).
   * Note: 'super()' must be the first call to satisfy class inheritance requirements.
   */
  constructor() {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'warn' },
      ],
      // Performance Tip: 'pretty' error formatting is reserved only for development to save CPU cycles in production.
      errorFormat: process.env.NODE_ENV === 'development' ? 'pretty' : 'colorless',
    });
  }

  /**
   * INITIALIZATION PROTOCOL
   * -----------------------
   * Executes the initial handshake with the Neon Cluster. 
   * Implements a "Fail-Fast" strategy: if the DB is unreachable, the system aborts to prevent unstable states.
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
   * Logic: Monitors query execution times and filters sensitive information.
   */
  private bindTelemetryEvents() {
    const isDev = process.env.NODE_ENV === 'development';

    /**
     * PERFORMANCE AUDITING:
     * High-speed logging for developers. Identifies slow SQL queries that could impact RTT.
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
     * Captures Prisma engine warnings to preemptively identify potential issues.
     */
    this.$on('warn', (e: Prisma.LogEvent) => {
      this.logger.warn(`⚠️ [PRISMA WARN] ${e.message}`);
    });

    /**
     * SECURITY SHIELD: PRODUCTION SANITIZATION
     * Critical Security Rule: Internal errors must NEVER be exposed in production logs
     * to prevent attackers from mapping the database structure.
     */
    this.$on('error', (e: Prisma.LogEvent) => {
      if (isDev) {
        this.logger.error(`❌ [PRISMA ERROR] ${e.message}`);
      } else {
        // PRODUCTION: Emit a generic reference for forensic team tracking.
        this.logger.error(`🚨 [CRITICAL DB ERROR] Internal Registry Operation Failed. [REF: ${Date.now()}]`);
      }
    });
  }

  /**
   * CRITICAL FAILURE HANDLER
   * -------------------------
   * Immediately terminates the process on database handshake failure.
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
   * Releases connection pools back to the cluster. Essential for Serverless platforms 
   * like Neon to prevent "Too Many Connections" errors.
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