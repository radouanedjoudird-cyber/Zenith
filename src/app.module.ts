import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module'; // تأكد أنه ينتهي بـ .module وليس .service
/**
 * SECURE ROOT APP MODULE
 * This is the central hub of Zenith Cloud.
 * SECURITY STRATEGY:
 * 1. Global Configuration: Load environment variables safely.
 * 2. Module Ordering: Database and Security modules are prioritized.
 * 3. Encapsulation: Controllers and services are scoped to prevent unauthorized access.
 */
@Module({
  imports: [
    /**
     * CONFIG MODULE (Recommended Security Addition):
     * Loads .env variables globally. Essential for protecting 
     * JWT secrets and DB credentials from being hardcoded.
     */
    ConfigModule.forRoot({
      isGlobal: true, // Makes configuration available everywhere
    }),

    /**
     * PRISMA MODULE:
     * The foundation of data integrity. Must be loaded early 
     * to establish secure DB connections.
     */
    PrismaModule,

    /**
     * AUTH MODULE:
     * Contains the Guards and Strategies that act as the 
     * security perimeter for the entire API.
     */
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    /**
     * APP SERVICE:
     * Handles core business logic outside of Auth/Database scopes.
     */
    AppService,
  ],
})
export class AppModule {}
