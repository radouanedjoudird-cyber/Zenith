import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

/**
 * ZENITH SECURE PRISMA MODULE - GLOBAL PERSISTENCE HUB v2.0
 * ---------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * SECURITY & PERFORMANCE STRATEGY:
 * 1. GLOBAL_SINGLETON: Ensures a single connection pool across the entire kernel.
 * 2. CONNECTION_LIMIT_PROTECTION: Prevents exhaustion (DoS) on Neon/PostgreSQL clusters.
 * 3. ENCAPSULATION: Masks complex ORM logic, exposing only the hardened service.
 * 4. IO_EFFICIENCY: Reduces overhead by reusing the same Prisma instance in all modules.
 */
@Global()
@Module({
  providers: [
    /**
     * EXPLICIT PROVIDER DEFINITION:
     * We use a single class provider to ensure the 'Zenith-Prisma-Engine'
     * is instantiated exactly once during the kernel boot sequence.
     */
    {
      provide: PrismaService,
      useClass: PrismaService,
    },
  ],
  exports: [
    /**
     * EXPOSURE CONTROL:
     * Exporting the Service makes it injectable globally (due to @Global),
     * enabling Auth, Users, and Audit modules to access the DB layer safely.
     */
    PrismaService,
  ],
})
export class PrismaModule {}