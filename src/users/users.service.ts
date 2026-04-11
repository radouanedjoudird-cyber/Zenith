import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDto } from './dto';

/**
 * ZENITH IDENTITY SERVICE - CORE ENGINE v2.6
 * -----------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURE: High-Performance User Lifecycle (PBAC Ready).
 * * * SECURITY STRATEGY: 
 * 1. ZERO-LEAK_PROJECTION: Surgical attribute whitelisting via 'safeProfile'.
 * 2. ATOMIC_CONSISTENCY: Ensures profile synchronization is transactionally safe.
 * 3. HASH_ROTATION: Dynamic re-salting for password updates (Work Factor 12).
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger('Zenith-Users-Engine');
  
  /**
   * DATA SHIELDING (PROJECTION): 
   * Whitelists only non-sensitive attributes. 
   * Passwords and HashedRTs are strictly isolated from the return stream.
   */
  private readonly safeProfile = { 
    id: true, 
    email: true, 
    firstName: true, 
    familyName: true, 
    role: true, 
    phoneNumber: true, 
    createdAt: true,
    permissions: {
      select: { action: true }
    }
  } as const;

  constructor(private prisma: PrismaService) {}

  /**
   * FETCH AUTHENTICATED IDENTITY
   * Surgical retrieval to minimize network RTT and memory footprint.
   */
  async getMe(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) {
      this.logger.error(`🚨 [IDENTITY_MISSING] Profile lookup failed for ID: ${userId}`);
      throw new NotFoundException('Zenith Identity: Profile not found.');
    }
    return user;
  }

  /**
   * PARTIAL IDENTITY SYNCHRONIZATION
   * Handles conditional hashing for passwords and updates user metadata.
   */
  async updateMe(userId: number, dto: UpdateUserDto) {
    try {
      const { password, ...otherData } = dto;
      const dataToUpdate: Prisma.UserUpdateInput = { ...otherData };

      /**
       * CONDITIONAL CRYPTOGRAPHY:
       * Only triggers bcrypt if a new password is provided in the DTO.
       * Work Factor 12 selected for balance between security and performance.
       */
      if (password) {
        dataToUpdate.password = await bcrypt.hash(password, 12);
        this.logger.warn(`🔐 [SECURITY_EVENT] Password rotation triggered for ID: ${userId}`);
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: dataToUpdate,
        select: this.safeProfile,
      });

      this.logger.log(`✅ [IDENTITY_SYNC] Profile synchronized for User: ${userId}`);
      return updatedUser;

    } catch (error) {
      this.handlePrismaError(error, userId);
    }
  }

  /**
   * IDENTITY TERMINATION PROTOCOL
   * IRREVERSIBLE: Purges the user identity from the Zenith registry.
   */
  async deleteMe(userId: number) {
    try {
      // Logic: Atomic delete operation.
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`💀 [IDENTITY_PURGE] Hard-delete executed for ID: ${userId}`);
      
      return { 
        status: 'SUCCESS', 
        message: 'Identity purged from Zenith Registry.' 
      };
    } catch (error) {
      throw new NotFoundException('Zenith Security: Target identity not found.');
    }
  }

  /**
   * GLOBAL DIRECTORY ACCESS (GOVERNANCE)
   * Returns all users sorted by creation date for administrative clarity.
   */
  async getAllUsers() {
    this.logger.debug('📊 [ADMIN_GOVERNANCE] Querying global registry.');
    return this.prisma.user.findMany({ 
      select: this.safeProfile,
      orderBy: { createdAt: 'desc' }
    });
  }

  /**
   * SURGICAL IDENTITY LOOKUP BY ID
   */
  async getUserById(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) throw new NotFoundException('Zenith Governance: Identity not found.');
    return user;
  }

  /**
   * DATABASE EXCEPTION MITIGATION
   * Standardizes raw Prisma errors into sanitized API responses 
   * to prevent DB-Schema leaking.
   */
  private handlePrismaError(error: any, userId: number) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      // P2002: Unique constraint violation (e.g. email already exists)
      if (error.code === 'P2002') {
        throw new ConflictException('Identity Conflict: Unique constraint violation (Email/Phone).');
      }
    }
    this.logger.error(`❌ [ENGINE_CRASH] Operation failed for ID ${userId}: ${error.message}`);
    throw new InternalServerErrorException('Zenith Engine: Fault in identity synchronization.');
  }
}