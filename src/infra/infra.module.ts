/**
 * @fileoverview ZENITH INFRASTRUCTURE KERNEL - RELIABILITY & STRESS ENGINE
 * @version 1.0.0
 */

import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { PrismaModule } from '../prisma/prisma.module';
import { InfraController } from './infra.controller';

@Module({
  imports: [
    TerminusModule, // NestJS official health check utility
    PrismaModule,   // To check Database connectivity
  ],
  controllers: [InfraController],
})
export class InfraModule {}