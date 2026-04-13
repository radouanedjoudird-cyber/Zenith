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
 * ZENITH IDENTITY SERVICE - CORE ENGINE v4.1 (MongoDB Edition)
 * -----------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURE: High-Performance User Lifecycle (PBAC Ready).
 * * * REFINEMENTS:
 * 1. MIGRATION: Shifted to String-based ObjectIDs for MongoDB local infra.
 * 2. ZERO-LEAK_PROJECTION: Surgical attribute whitelisting via 'safeProfile'.
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
   * @param userId MongoDB ObjectId (String)
   */
  async getMe(userId: string) {
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
  async updateMe(userId: string, dto: UpdateUserDto) {
    try {
      const { password, ...otherData } = dto;
      const dataToUpdate: Prisma.UserUpdateInput = { ...otherData };

      if (password) {
        dataToUpdate.password = await bcrypt.hash(password, 12);
        this.logger.warn(`🔐 [SECURITY_EVENT] Password rotation triggered for Identity: ${userId}`);
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: dataToUpdate,
        select: this.safeProfile,
      });

      this.logger.log(`✅ [IDENTITY_SYNC] Profile synchronized for Identity: ${userId}`);
      return updatedUser;

    } catch (error) {
      this.handlePrismaError(error, userId);
    }
  }

  /**
   * IDENTITY TERMINATION PROTOCOL
   * IRREVERSIBLE: Purges the user identity from the Zenith registry.
   */
  async deleteMe(userId: string) {
    try {
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`💀 [IDENTITY_PURGE] Hard-delete executed for Identity: ${userId}`);
      
      return { 
        status: 'SUCCESS', 
        message: 'Identity purged from Zenith Registry.' 
      };
    } catch (error) {
      this.logger.error(`❌ [PURGE_FAILURE] Target not found for ID: ${userId}`);
      throw new NotFoundException('Zenith Security: Target identity not found.');
    }
  }

  /**
   * GLOBAL DIRECTORY ACCESS (GOVERNANCE)
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
  async getUserById(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) throw new NotFoundException('Zenith Governance: Identity not found.');
    return user;
  }

  /**
   * DATABASE EXCEPTION MITIGATION
   */
  private handlePrismaError(error: any, userId: string) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        throw new ConflictException('Identity Conflict: Unique constraint violation (Email/Phone).');
      }
    }
    this.logger.error(`❌ [ENGINE_CRASH] Operation failed for ID ${userId}: ${error.message}`);
    throw new InternalServerErrorException('Zenith Engine: Fault in identity synchronization.');
  }
}