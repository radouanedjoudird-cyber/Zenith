import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDto } from './dto';

/**
 * ZENITH USERS SERVICE - ENTERPRISE EDITION
 * -----------------------------------------
 * CORE RESPONSIBILITIES: Profile Management & Administrative Governance.
 * SECURITY: Implements strict data selection (Whitelisting) & Cryptographic hashing.
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  
  // SAFE DATA PROJECTION: Prevents accidental exposure of sensitive credentials.
  private readonly safeProfile = { 
    id: true, 
    email: true, 
    firstName: true, 
    familyName: true, 
    role: true, 
    phoneNumber: true, 
    createdAt: true,
    updatedAt: true
  };

  constructor(private prisma: PrismaService) {}

  /**
   * SELF: Fetch authenticated user profile.
   * INTEGRITY: Ensures the User ID is valid before querying Prisma.
   */
  async getMe(userId: number) {
    if (!userId) {
      this.logger.error('[ID_VOID] Profile lookup attempted with undefined ID.');
      throw new NotFoundException('Zenith Identity Error: Session invalid.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) throw new NotFoundException('Identity Record: Profile not found.');
    return user;
  }

  /**
   * SELF: Update profile with partial update support.
   * SECURITY: Re-hashes password using high-entropy rounds if provided.
   */
  async updateMe(userId: number, dto: UpdateUserDto) {
    try {
      if (dto.password) {
        dto.password = await bcrypt.hash(dto.password, 12);
      }
      
      const updated = await this.prisma.user.update({
        where: { id: userId },
        data: dto,
        select: this.safeProfile,
      });

      this.logger.log(`[IDENTITY_SYNC] User ${userId} profile updated successfully.`);
      return updated;
    } catch (error) {
      if (error.code === 'P2002') throw new ConflictException('Identity Conflict: Data already in use.');
      this.logger.error(`[UPDATE_FAILED] ID ${userId}: ${error.message}`);
      throw new InternalServerErrorException('Enterprise Operation: Update failed.');
    }
  }

  /**
   * SELF: Permanent account removal.
   * DESTRUCTION: Cascading delete handled by database constraints.
   */
  async deleteMe(userId: number) {
    try {
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`[ACCOUNT_PURGED] User ID ${userId} has been removed from Zenith.`);
      return { success: true, message: 'Your account has been permanently removed.' };
    } catch (error) {
      throw new NotFoundException('Deletion Error: User identity not found.');
    }
  }

  // ==========================================
  // ADMIN PRIVILEGED OPERATIONS (RBAC Ready)
  // ==========================================

  /**
   * ADMIN: Bulk fetch all registered identities.
   */
  async getAllUsers() {
    this.logger.debug('[ADMIN_GOVERNANCE] Fetching global user directory.');
    return this.prisma.user.findMany({ 
      select: this.safeProfile,
      orderBy: { createdAt: 'desc' }
    });
  }

  /**
   * ADMIN/MODERATOR: Precise lookup of any user by ID.
   */
  async getUserById(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) {
      this.logger.warn(`[ADMIN_LOOKUP_FAIL] No record found for ID: ${userId}`);
      throw new NotFoundException('Enterprise Governance: User record not found.');
    }
    return user;
  }
}