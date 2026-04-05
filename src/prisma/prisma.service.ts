import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';

/**
 * SECURE PRISMA SERVICE - ZENITH CLOUD
 * SECURITY STRATEGY:
 * 1. Query Obfuscation: Queries are never logged in production to prevent PII leaks.
 * 2. Graceful Shutdown: Prevents zombie connections that exhaust DB resources.
 * 3. Intelligent Error Logging: Full error details in development, masked in production.
 *    In production, errors should be forwarded to an external monitoring tool (e.g. Sentry).
 */
@Injectable()
export class PrismaService
  extends PrismaClient<Prisma.PrismaClientOptions, 'query' | 'error' | 'warn'>
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);
  private readonly isDevelopment = process.env.NODE_ENV === 'development';

  constructor() {
    super({
      log: [
        { emit: 'event', level: 'query' },
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'warn' },
        { emit: 'stdout', level: 'info' },
      ],
    });
  }

  async onModuleInit() {
    try {
      await this.$connect();
      this.logger.log('✅ Connection to Neon Database established.');

      /**
       * QUERY LOGGING (Development Only):
       * Full query details are logged in development for debugging purposes.
       * In production, logging queries is a high-risk information leak (PII exposure).
       */
      if (this.isDevelopment) {
        this.$on('query', (e: Prisma.QueryEvent) => {
          this.logger.debug(`[Query] ${e.query} | Duration: ${e.duration}ms`);
        });
      }

      /**
       * WARN LOGGING (Development Only):
       * Prisma warnings (e.g. slow queries, deprecated features) are visible
       * only in development to assist debugging without polluting production logs.
       */
      if (this.isDevelopment) {
        this.$on('warn', (e: Prisma.LogEvent) => {
          this.logger.warn(`[Prisma Warning] ${e.message}`);
        });
      }

      /**
       * INTELLIGENT ERROR LOGGING:
       * - Development: Full error details are shown to help the developer debug.
       * - Production: Error details are masked to prevent internal information leakage.
       *   In a real production environment, replace the logger.error call with
       *   a Sentry.captureException(e) or equivalent monitoring tool.
       */
      this.$on('error', (e: Prisma.LogEvent) => {
        if (this.isDevelopment) {
          this.logger.error(`[Prisma Error] ${e.message} | Target: ${e.target}`);
        } else {
          // PRODUCTION: Never expose internal DB error details externally.
          // Forward to Sentry or equivalent: Sentry.captureException(e)
          this.logger.error(`[Prisma Error] An internal database error occurred.`);
        }
      });

    } catch (error) {
      /**
       * CRITICAL FAILURE:
       * If the database connection fails at startup, we immediately terminate
       * the process to prevent the application from running in an inconsistent state.
       */
      this.logger.error('❌ Critical: Database handshake failed.');
      if (this.isDevelopment) {
        this.logger.error(`Detail: ${error.message}`);
      }
      process.exit(1);
    }
  }

  /**
   * GRACEFUL SHUTDOWN:
   * Properly closes all database connections when the application shuts down.
   * Essential for cloud environments (Neon/AWS) to free up the connection pool
   * and prevent resource exhaustion.
   */
  async onModuleDestroy() {
    try {
      await this.$disconnect();
      this.logger.warn('⚠️ Database connections closed. Resource cleanup complete.');
    } catch (error) {
      this.logger.error(`[Shutdown Error] Failed to close database connections: ${error.message}`);
    }
  }
}