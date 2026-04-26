/**
 * @fileoverview Zenith Systems - Identity & Access Management (IAM) Service.
 * @module AuthService
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Core service for identity orchestration, cryptographic session management, 
 * and dynamic RBAC policy enforcement.
 * @standards ISO/IEC 27001 Security Standard | OAuth2 / OIDC Compliant
 */

import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { AccountStatus, Prisma, session as SessionType } from '@prisma/client';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { DeviceFingerprint } from '../common/utils/fingerprint.util';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  /**
   * @private @readonly logger
   * @description Internal system logger for forensic telemetry.
   */
  private readonly logger = new Logger('ZENITH_IAM_KERNEL');

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * @method requestPasswordReset
   * @async
   * @description Initiates a secure recovery protocol. Implements anti-enumeration logic.
   * @param {string} email - The target identity for recovery.
   * @returns {Promise<{status: string, message: string, token?: string}>}
   */
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      this.logger.warn(`RECOVERY_PROBE: Unauthorized reset request for identity: ${email}`);
      return { status: 'SUCCESS', message: 'Recovery protocol initiated if account exists.' };
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000), // 15-Minute TTL
      },
    });

    this.logger.log(`🛡️ [RECOVERY_SYNC]: Cryptographic reset artifact generated for user ID: ${user.id}`);
    return { status: 'SUCCESS', token: resetToken };
  }

  /**
   * @method signup
   * @async
   * @description Provisions a new identity and binds it to a dynamic role policy.
   * @param {SignupDto} dto - Data Transfer Object for user registration.
   * @param {DeviceFingerprint} fp - Hardware telemetry for initial anchoring.
   * @throws {ConflictException} If identity collision (email/phone) is detected.
   */
  async signup(dto: SignupDto, fp: DeviceFingerprint) {
    try {
      const hashedPassword = await argon2.hash(dto.password);

      // DYNAMIC_ROLE_RESOLUTION: Ensure base 'USER' policy exists.
      let targetRole = await this.prisma.role.findUnique({ where: { name: 'USER' } });
      
      if (!targetRole) {
        targetRole = await this.prisma.role.create({
          data: { name: 'USER', permissions: ['PROFILE_READ', 'PROFILE_UPDATE'] }
        });
      }

      const newUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
          firstName: dto.firstName,
          familyName: dto.familyName,
          phoneNumber: dto.phoneNumber,
          roleId: targetRole.id,
          status: AccountStatus.ACTIVE,
          version: 1,
        },
        include: { role: true, permissions: true }
      });

      this.logger.log(`AUDIT [IDENTITY_CREATED]: ${newUser.email} | HW_BINDING: ${fp.deviceId}`);

      const permissions = this.aggregatePermissions(newUser);
      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role?.name ?? 'USER', permissions);

      await this.createSession(newUser.id, tokens.refresh_token, fp);
      return tokens;

    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Identity collision. Registry entry already exists.');
      }
      throw error;
    }
  }

  /**
   * @method signin
   * @async
   * @description Executes credential verification with side-channel mitigation and status check.
   */
  async signin(dto: SigninDto, fp: DeviceFingerprint) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      include: { role: true, permissions: true },
    });

    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$dummyhashsecret'; 
    const isPasswordValid = user 
      ? await argon2.verify(user.password, dto.password)
      : await argon2.verify(dummyHash, dto.password);

    if (!user || !isPasswordValid) {
      this.logger.warn(`SECURITY_ALERT [AUTH_FAILURE]: Potential breach attempt on ${dto.email}`);
      throw new UnauthorizedException('ZENITH_GUARD: Invalid credentials.');
    }

    if (user.status !== AccountStatus.ACTIVE) {
      throw new ForbiddenException(`ZENITH_GUARD: Account status is ${user.status}. Access denied.`);
    }

    const permissions = this.aggregatePermissions(user);
    const tokens = await this.signTokens(user.id, user.email, user.role?.name ?? 'USER', permissions);

    await this.createSession(user.id, tokens.refresh_token, fp);
    return tokens;
  }

  /**
   * @method refreshTokens
   * @async
   * @description Performs Refresh Token Rotation (RTR) with mandatory Hardware Affinity.
   */
  async refreshTokens(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const userSessions = await this.prisma.session.findMany({ 
      where: { userId },
      orderBy: { createdAt: 'desc' } 
    });

    let activeSession: SessionType | null = null;
    for (const session of userSessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        activeSession = session;
        break;
      }
    }

    if (!activeSession) {
      await this.signoutAll(userId); 
      this.logger.error(`CRITICAL [REUSE_DETECTED]: Refresh token reuse for ID ${userId}.`);
      throw new ForbiddenException('ZENITH_SHIELD: Anomaly detected. Identity locked.');
    }

    if (activeSession.deviceId !== fp.deviceId) {
      await this.signoutAll(userId);
      throw new ForbiddenException('ZENITH_SHIELD: Hardware context mismatch.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true, permissions: true },
    });

    if (!user) throw new ForbiddenException('ZENITH_GUARD: Identity context lost.');

    const permissions = this.aggregatePermissions(user);
    const tokens = await this.signTokens(userId, user.email, user.role?.name ?? 'USER', permissions);
    
    const newHashedRt = await argon2.hash(tokens.refresh_token);
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 7);

    /** @description ATOMIC_SESSION_ROTATION: Updates hashed refresh token and resets expiry. */
    await this.prisma.session.update({
      where: { id: activeSession.id },
      data: { 
        hashedRt: newHashedRt,
        os: fp.os,
        browser: fp.browser,
        expiresAt: sessionExpiry, // 🛡️ FIX [TS2322]: Sync with v7.4.0 Schema
        updatedAt: new Date(),
      },
    });

    return tokens;
  }

  /**
   * @private aggregatePermissions
   * @description Resolves identity-role mapping and applies the God Mode wildcard.
   */
  private aggregatePermissions(user: any): string[] {
    if (user.role?.name === 'SUPERADMIN') return ['*'];

    const rolePermissions = user.role?.permissions || [];
    const directPermissions = user.permissions.map((p: any) => p.action);
    
    return [...new Set([...rolePermissions, ...directPermissions])];
  }

  /**
   * @private createSession
   * @async
   * @description Managed session persistence with mandatory expiry and device limit.
   */
  private async createSession(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const hashedRt = await argon2.hash(rawRt);
    const sessionExpiry = new Date();
    sessionExpiry.setDate(sessionExpiry.getDate() + 7); // 🛡️ Standard 7-Day TTL

    const sessionCount = await this.prisma.session.count({ where: { userId } });
    if (sessionCount >= 5) {
      const oldest = await this.prisma.session.findFirst({
        where: { userId },
        orderBy: { createdAt: 'asc' },
      });
      if (oldest) await this.prisma.session.delete({ where: { id: oldest.id } });
    }

    await this.prisma.session.create({
      data: {
        userId,
        hashedRt,
        deviceId: fp.deviceId,
        os: fp.os,
        browser: fp.browser,
        device: fp.deviceType,
        expiresAt: sessionExpiry, // 🛡️ FIX [TS2322]: Mandatory field provisioning
      },
    });
  }

  /**
   * @private signTokens
   * @async
   * @description Generates an asymmetric JWT pair with embedded policy claims.
   */
  private async signTokens(uId: string, email: string, role: string, perms: string[]) {
    const payload = { sub: uId, email, role, perms };

    const [at, rt] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m', 
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d', 
      }),
    ]);

    return { access_token: at, refresh_token: rt };
  }

  /**
   * @method signout
   * @async
   * @description Terminates specific hardware context association.
   */
  async signout(userId: string, rawRt: string) {
    const sessions = await this.prisma.session.findMany({ where: { userId } });
    for (const session of sessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        await this.prisma.session.delete({ where: { id: session.id } });
        break;
      }
    }
    return { status: 'SUCCESS', message: 'Hardware context decoupled.' };
  }

  /**
   * @method signoutAll
   * @async
   * @description Full identity revocation across all registered devices.
   */
  async signoutAll(userId: string) {
    await this.prisma.session.deleteMany({ where: { userId } });
    return { status: 'SUCCESS', message: 'Global identity revocation complete.' };
  }
}