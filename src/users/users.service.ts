import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDto } from './dto';

/**
 * ZENITH USERS SERVICE - ENTERPRISE EDITION
 * -----------------------------------------
 * CORE RESPONSIBILITIES: Profile Management & Admin Governance.
 * SECURITY: Implements strict data selection and cryptographic hashing.
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  // SAFE DATA PROJECTION: Centralized source of truth for public fields.
  private readonly safeUserFields = {
    id: true,
    email: true,
    firstName: true,
    familyName: true,
    phoneNumber: true,
    createdAt: true,
    updatedAt: true,
    // We strictly EXCLUDE 'password' and 'hashedRt' here.
  } as const;

  constructor(private prisma: PrismaService) {}

  /**
   * SELF: Fetch authenticated user's own profile.
   */
  async getMe(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeUserFields,
    });

    if (!user) {
      this.logger.error(`[AUTH_FAILURE] Profile lookup failed for ID: ${userId}`);
      throw new NotFoundException('Your profile was not found.');
    }
    return user;
  }

  /**
   * SELF: Update profile with partial data support.
   */
  async updateMe(userId: number, dto: UpdateUserDto) {
    try {
      const { password, ...otherData } = dto;
      const dataToUpdate: any = { ...otherData };

      // PASSWORD MANAGEMENT: Robust hashing for security updates.
      if (password) {
        dataToUpdate.password = await bcrypt.hash(password, 12);
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: dataToUpdate,
        select: this.safeUserFields,
      });

      this.logger.log(`[USER_UPDATE] User ID ${userId} updated successfully.`);
      return updatedUser;
    } catch (error) {
      // Conflict Handling (Email/Phone duplication)
      if (error.code === 'P2002') {
        throw new ConflictException('Identity Conflict: Email or Phone already registered.');
      }
      this.logger.error(`[UPDATE_ERROR] User ID ${userId}: ${error.message}`);
      throw new InternalServerErrorException('Profile update failed.');
    }
  }

  /**
   * SELF: Permanent account removal.
   */
  async deleteMe(userId: number) {
    try {
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`[ACCOUNT_DELETED] User ID ${userId} has left the system.`);
      return { success: true, message: 'Your account has been permanently removed.' };
    } catch (error) {
      throw new NotFoundException('Account deletion failed: User not found.');
    }
  }

  // ==========================================
  // ADMIN PRIVILEGED OPERATIONS (RBAC Ready)
  // ==========================================

  /**
   * ADMIN: Bulk fetch all registered users.
   */
  async getAllUsers() {
    this.logger.debug('[ADMIN_ACTION] Fetching all user records.');
    return await this.prisma.user.findMany({
      select: this.safeUserFields,
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * ADMIN/MODERATOR: Precise lookup of any user.
   */
  async getUserById(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeUserFields,
    });

    if (!user) {
      this.logger.warn(`[ADMIN_LOOKUP] Failed for ID: ${userId}`);
      throw new NotFoundException('User record not found.');
    }
    return user;
  }
}