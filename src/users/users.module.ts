import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

/**
 * ZENITH USERS MICRO-MODULE (IDENTITY GOVERNANCE)
 * -----------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL DESIGN:
 * 1. RESOURCE_ISOLATION: Encapsulates all identity-related operations.
 * 2. DEPENDENCY_INJECTION: Leverages NestJS IoC for seamless service orchestration.
 * 3. EXPORT_STRATEGY: Exposes UsersService for cross-module integration (e.g., Auth/Audit).
 * 4. PERFORMANCE: Optimized singleton lifecycle for low-latency execution.
 */
@Module({
  /**
   * CONTROLLERS:
   * Registers the API ingress points for identity lifecycle management.
   * Handles v1 routing and permission-gated endpoints.
   */
  controllers: [UsersController],

  /**
   * PROVIDERS:
   * UsersService: The core engine for profile manipulation and administrative governance.
   * Interacts directly with Prisma for high-performance I/O operations.
   */
  providers: [UsersService],

  /**
   * EXPORTS:
   * Crucial for the 'Defense-in-Depth' strategy. By exporting UsersService,
   * we allow the AuthModule and other internal kernels to perform identity 
   * lookups while maintaining clean architectural boundaries.
   */
  exports: [UsersService],
})
export class UsersModule {}