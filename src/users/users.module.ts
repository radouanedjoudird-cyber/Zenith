import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

/**
 * USERS MODULE
 * ------------
 * Bridges the Controller and Service for user management.
 * Provides the UsersService to other modules if needed via Exports.
 */
@Module({
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // Standard practice: Export service for Auth/Admin use.
})
export class UsersModule {}