import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDto } from './dto';

/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) CORE KERNEL
 * ============================================================================
 * @class UsersService
 * @module IdentityModule
 * @description Centralized identity lifecycle engine for the Zenith ecosystem.
 * Implements high-availability data access patterns, secure attribute projection,
 * and cryptographic integrity for user metadata.
 *
 * SECURITY PROTOCOLS:
 * - Attribute Isolation: Using 'IdentityProjection' to prevent PII leakage.
 * - Credential Hardening: Argon2id salt-based hashing for secure rotation.
 * - Error Sanitization: Obfuscating database internals via Prisma error mapping.
 *
 * @author Radouane Djoudi
 * @version 7.4.0 (Distributed Systems Optimized)
 * ============================================================================
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger('ZENITH_IAM_ENGINE');

  /**
   * IDENTITY PROJECTION MATRIX
   * Defines a strict whitelist for data exposure across the API layer.
   */
  private readonly identityProjection: Prisma.userSelect = {
    id: true,
    email: true,
    firstName: true,
    familyName: true,
    role: true,
    phoneNumber: true,
    status: true,
    version: true,
    createdAt: true,
    permissions: {
      select: { action: true },
    },
  };

  constructor(private readonly prisma: PrismaService) {}

  /**
   * @method getMe
   * @description Retrieves the authenticated identity context from the registry.
   * @param {string} userId - Target identity UUID.
   * @returns {Promise<Partial<User>>} Sanitized identity profile.
   */
  async getMe(userId: string) {
    if (!userId) {
      this.logger.error('CRITICAL_GATE: Attempted lookup with null identity pointer.');
      throw new InternalServerErrorException('ZENITH_CORE: Identity pointer corrupted.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.identityProjection,
    });

    if (!user) {
      this.logger.warn(`AUDIT_FAILURE [LOOKUP]: Identity ${userId} not present in registry.`);
      throw new NotFoundException('ZENITH_IAM: Profile context missing.');
    }

    return user;
  }

  /**
   * @method updateMe
   * @description Orchestrates partial identity synchronization and credential rotation.
   * @param {string} userId - Target identity UUID.
   * @param {UpdateUserDto} dto - Payload containing modified attributes.
   */
  async updateMe(userId: string, dto: UpdateUserDto) {
    try {
      const { password, ...payload } = dto;
      
      // Strict Type Casting for Prisma Kernel
      const mutationData: Prisma.userUpdateInput = { ...payload };

      if (password) {
        mutationData.password = await argon2.hash(password);
        // Incrementing version for cryptographic session invalidation
        mutationData.version = { increment: 1 };
        this.logger.warn(`SECURITY_EVENT [ROTATION]: Credential upgrade triggered for ${userId}`);
      }

      const updatedIdentity = await this.prisma.user.update({
        where: { id: userId },
        data: mutationData,
        select: this.identityProjection,
      });

      this.logger.log(`AUDIT_SUCCESS [SYNC]: Identity ${userId} successfully synchronized.`);
      return updatedIdentity;

    } catch (error) {
      this.handleKernelException(error, userId);
    }
  }

  /**
   * @method deleteMe
   * @description Executes a high-integrity purge of the target identity from the system.
   */
  async deleteMe(userId: string) {
    try {
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`AUDIT_ALERT [PURGE]: Identity ${userId} permanently decommissioned.`);
      
      return {
        status: 'TERMINATED',
        timestamp: new Date().toISOString(),
        message: 'Identity successfully purged from Zenith Core Registry.',
      };
    } catch (error) {
      this.logger.error(`FAULT [PURGE_FAILURE]: Decommissioning failed for ${userId}.`);
      throw new NotFoundException('ZENITH_IAM: Identity target not found for termination.');
    }
  }

  /**
   * @method getAllUsers (Admin Scope)
   * @description Returns a high-level telemetry list of all registered identities.
   */
  async getAllUsers() {
    this.logger.debug('GOVERNANCE_QUERY: Accessing global identity registry.');
    return this.prisma.user.findMany({
      select: this.identityProjection,
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * @method getUserById (Elevated Scope)
   */
  async getUserById(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.identityProjection,
    });

    if (!user) {
      throw new NotFoundException(`ZENITH_IAM: Identity [${userId}] not found.`);
    }
    return user;
  }

  /**
   * @private @method handleKernelException
   * @description Maps Prisma low-level faults to standard HTTP exceptions.
   */
  private handleKernelException(error: any, contextId: string) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Conflict - Unique attribute collision detected.');
      }
    }
    
    this.logger.error(`KERNEL_PANIC: Sync failure for ${contextId} | Trace: ${error.message}`);
    throw new InternalServerErrorException('ZENITH_KERNEL: Identity synchronization fault.');
  }
}