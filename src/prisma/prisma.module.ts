import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

/**
 * SECURE PRISMA DATABASE MODULE - ZENITH CLOUD
 * SECURITY STRATEGY:
 * 1. Global Singleton: Prevents "Connection Exhaustion" (DoS) by reusing a single pool.
 * 2. Encapsulation: Only exports the Service, hiding the underlying DB engine logic.
 * 3. Lifecycle Management: PrismaService handles its own clean disconnects.
 */
@Global()
@Module({
  providers: [
    {
      /**
       * EXPLICIT PROVIDER DEFINITION:
       * Ensures that the PrismaService is instantiated exactly once.
       * This is critical for maintaining connection limits on Neon/PostgreSQL.
       */
      provide: PrismaService,
      useClass: PrismaService,
    },
  ],
  exports: [
    /**
     * EXPOSURE CONTROL:
     * We only export the Service. Any module using this must follow 
     * the security patterns we've defined in PrismaService (like logging control).
     */
    PrismaService,
  ],
})
export class PrismaModule {}