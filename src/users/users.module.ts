import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

/**
 * ZENITH USERS MICRO-MODULE (IDENTITY GOVERNANCE)
 * -----------------------------------------------
 * ARCHITECTURE:
 * Encapsulates all identity-related operations, ensuring strict isolation 
 * of User resources and business logic.
 * * DESIGN PRINCIPLES:
 * 1. DEPENDENCY INJECTION: Managed by NestJS IoC container for high testability.
 * 2. SINGLETON INTEGRITY: UsersService is shared across the application context.
 * 3. INFRASTRUCTURE: Tailored for high-performance execution on HP-ProBook.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Module({
  /**
   * CONTROLLERS:
   * Defines the API entry points for Zenith Identity & Access Management.
   */
  controllers: [UsersController],

  /**
   * PROVIDERS:
   * UsersService: The core engine for profile management and administrative lookups.
   */
  providers: [UsersService],

  /**
   * EXPORTS:
   * Enables other modules (e.g., AuthModule, AuditModule) to perform user 
   * operations without circular dependency risks.
   */
  exports: [UsersService],
})
export class UsersModule {}