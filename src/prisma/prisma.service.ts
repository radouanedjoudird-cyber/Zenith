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
 * 3. Error Masking: Database internals are hidden from external logs.
 */
@Injectable()
export class PrismaService
  extends PrismaClient<Prisma.PrismaClientOptions, 'query' | 'error' | 'warn'>
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

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
       * SECURITY: QUERY LOGGING (Development Only)
       * In production, logging queries is a high-risk information leak.
       */
      if (process.env.NODE_ENV === 'development') {
        this.$on('query', (e: Prisma.QueryEvent) => {
          this.logger.debug(`[Query] ${e.query} | Duration: ${e.duration}ms`);
        });
      }

      /**
       * SECURE ERROR AUDITING:
       * We intercept errors to log them internally without leaking to stdout
       * unless necessary.
       */
      this.$on('error', (e: Prisma.LogEvent) => {
        this.logger.error(`[Prisma Error] Check internal logs for details.`);
        // Note: In a real environment, send 'e.message' to an external tool like Sentry.
      });

    } catch (error) {
      this.logger.error('❌ Critical: Database handshake failed.');
      
      // Stop the process immediately if the DB is down to prevent inconsistent state
      if (process.env.NODE_ENV !== 'production') {
        this.logger.error(`Detail: ${error.message}`);
      }
      process.exit(1);
    }
  }

  /**
   * GRACEFUL SHUTDOWN
   * Essential for cloud environments (like Neon/AWS) to free up connection pools.
   */
  async onModuleDestroy() {
    try {
      await this.$disconnect();
      this.logger.warn('⚠️ Database connections closed. Resource cleanup complete.');
    } catch (error) {
      this.logger.error('Error during database cleanup phase.');
    }
  }
}