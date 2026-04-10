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
 * ARCHITECTURE: High-Performance User Lifecycle Management (PBAC Ready).
 * STRATEGY: 
 * 1. ZERO-LEAK PROJECTION: Multi-layer attribute whitelisting.
 * 2. PERFORMANCE TUNING: Intelligent selection to minimize RTT with Neon DB.
 * 3. SECURITY INTEGRITY: Dynamic salt rounds and error masking.
 * * @author Radouane Djoudi
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger('Zenith-Users-Engine');
  
  /**
   * DATA SHIELDING: 
   * Whitelists only safe attributes. Password & Tokens are isolated by default.
   */
  private readonly safeProfile = { 
    id: true, 
    email: true, 
    firstName: true, 
    familyName: true, 
    role: true, 
    phoneNumber: true, 
    createdAt: true,
    // Including permissions count or names can be useful for UI hydration
    permissions: {
      select: { action: true }
    }
  } as const;

  constructor(private prisma: PrismaService) {}

  /**
   * FETCH AUTHENTICATED IDENTITY
   * Uses 'select' for surgical data retrieval, reducing database payload.
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
   * Optimized to handle high-frequency profile updates with atomic consistency.
   */
  async updateMe(userId: number, dto: UpdateUserDto) {
    try {
      // 1. Prepare data and handle conditional hashing
      const { password, ...otherData } = dto;
      const dataToUpdate: Prisma.UserUpdateInput = { ...otherData };

      if (password) {
        dataToUpdate.password = await bcrypt.hash(password, 12);
        this.logger.warn(`🔐 [SECURITY_EVENT] Password rotation triggered for ID: ${userId}`);
      }

      // 2. Atomic update with surgical selection
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
   * Warning: This operation is irreversible and audited by the forensic engine.
   */
  async deleteMe(userId: number) {
    try {
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
   * GLOBAL DIRECTORY ACCESS (Admin Only)
   * Performance: Implements descending order by default for governance clarity.
   */
  async getAllUsers() {
    this.logger.debug('📊 [ADMIN_GOVERNANCE] Querying global registry.');
    return this.prisma.user.findMany({ 
      select: this.safeProfile,
      orderBy: { createdAt: 'desc' }
    });
  }

  /**
   * SURGICAL IDENTITY LOOKUP
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
   * ERROR MITIGATION HANDLER
   * Standardizes database exceptions into clear, secure API responses.
   */
  private handlePrismaError(error: any, userId: number) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        throw new ConflictException('Identity Conflict: Unique constraint violation (Email/Phone).');
      }
    }
    this.logger.error(`❌ [ENGINE_CRASH] Operation failed for ID ${userId}: ${error.message}`);
    throw new InternalServerErrorException('Zenith Engine: Fault in identity synchronization.');
  }
}