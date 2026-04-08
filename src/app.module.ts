import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';

/**
 * SECURE ROOT APP MODULE
 * ----------------------
 * This is the central hub of Zenith Cloud.
 * * SECURITY STRATEGY:
 * 1. Global Configuration: Load environment variables safely via ConfigModule.
 * 2. Module Ordering: Prisma and Auth are prioritized to establish the security perimeter.
 * 3. Domain Logic: UsersModule is integrated to handle profile and account management.
 */
@Module({
  imports: [
    /**
     * CONFIG MODULE:
     * Loads .env variables globally. Essential for protecting 
     * JWT secrets and DB credentials from being hardcoded.
     */
    ConfigModule.forRoot({
      isGlobal: true, 
    }),

    /**
     * PRISMA MODULE:
     * The foundation of data integrity. Must be loaded early 
     * to establish secure DB connections for all other modules.
     */
    PrismaModule,

    /**
     * AUTH MODULE:
     * Contains the Guards and Strategies (JWT AT/RT) that act as the 
     * security perimeter for the entire Zenith Cloud API.
     */
    AuthModule,

    /**
     * USERS MODULE:
     * Handles all user-related business logic, including profile updates,
     * account deletion, and administrative user management.
     */
    UsersModule,
  ],
  controllers: [AppController],
  providers: [
    /**
     * APP SERVICE:
     * Handles top-level core business logic and system health checks.
     */
    AppService,
  ],
})
export class AppModule {}