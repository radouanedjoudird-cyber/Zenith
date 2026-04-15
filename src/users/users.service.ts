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
 * ZENITH IDENTITY SERVICE - CORE KERNEL v5.0 (Security Hardened)
 * -----------------------------------------------------------
 * @class UsersService
 * @description Enterprise-grade user lifecycle management for Zenith.
 * Implements high-integrity identity synchronization and secure attribute projection.
 * * * SECURITY ARCHITECTURE:
 * 1. CRYPTOGRAPHY: Argon2id hashing for zero-knowledge credential persistence.
 * 2. DATA SHIELDING: Surgical 'safeProfile' projection to mitigate PII leakage.
 * 3. AUDIT LOGGING: Real-time telemetry for identity mutations and lifecycle events.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger('ZENITH_IDENTITY_ENGINE');
  
  /**
   * IDENTITY PROJECTION MATRIX: 
   * Strict whitelist of non-sensitive attributes for API responses.
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
   * @method getMe
   */
  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) {
      this.logger.error(`AUDIT_FAILURE [IDENTITY_MISSING]: Profile lookup failed for ${userId}`);
      throw new NotFoundException('ZENITH_IAM: Identity context not found.');
    }
    return user;
  }

  /**
   * @method updateMe
   * @description Performs partial identity synchronization with credential rotation.
   */
  async updateMe(userId: string, dto: UpdateUserDto) {
    try {
      const { password, ...otherData } = dto;
      
      /**
       * 🟢 FIX: Changed Prisma.UserUpdateInput to Prisma.userUpdateInput (lowercase 'u')
       * to align with the generated Prisma client types.
       */
      const dataToUpdate: Prisma.userUpdateInput = { ...otherData };

      if (password) {
        dataToUpdate.password = await argon2.hash(password);
        this.logger.warn(`SECURITY_EVENT [CREDENTIAL_ROTATION]: Password hash upgraded for ${userId}`);
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: dataToUpdate,
        select: this.safeProfile,
      });

      this.logger.log(`AUDIT_SUCCESS [IDENTITY_SYNC]: Profile synchronized for ${userId}`);
      return updatedUser;

    } catch (error) {
      this.handlePrismaError(error, userId);
    }
  }

  /**
   * @method deleteMe
   */
  async deleteMe(userId: string) {
    try {
      await this.prisma.user.delete({ where: { id: userId } });
      this.logger.warn(`SECURITY_ALERT [IDENTITY_PURGE]: Hard-delete executed for identity ${userId}`);
      
      return { 
        status: 'OK', 
        message: 'Identity successfully purged from Zenith Registry.' 
      };
    } catch (error) {
      this.logger.error(`AUDIT_ERROR [PURGE_FAILURE]: Target identity ${userId} not found.`);
      throw new NotFoundException('ZENITH_IAM: Termination target not found.');
    }
  }

  /**
   * @method getAllUsers
   */
  async getAllUsers() {
    this.logger.debug('AUDIT_LOG [GOVERNANCE]: Querying global identity registry.');
    return this.prisma.user.findMany({ 
      select: this.safeProfile,
      orderBy: { createdAt: 'desc' }
    });
  }

  /**
   * @method getUserById
   */
  async getUserById(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: this.safeProfile,
    });

    if (!user) throw new NotFoundException('ZENITH_IAM: Requested identity not found.');
    return user;
  }

  /**
   * @private @method handlePrismaError
   */
  private handlePrismaError(error: any, userId: string) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Unique constraint violation (Email/Phone collision).');
      }
    }
    this.logger.error(`CRITICAL_FAULT [ENGINE_SYNC]: Operation failed for ${userId} | ${error.message}`);
    throw new InternalServerErrorException('ZENITH_KERNEL: Identity synchronization fault.');
  }
}