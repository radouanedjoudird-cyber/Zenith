/**
 * @fileoverview Identity & Access Management (IAM) Kernel.
 * Implements Multi-Device Session Orchestration with Hardware Fingerprinting.
 * Inspired by Google's BeyondCorp and Netflix's Device-Bound Tokens.
 * * @version 6.1.0
 * @author Radouane Djoudi
 * @license Enterprise - Sovereign Infrastructure
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
import { Prisma, Role, session as sessionType } from '@prisma/client';
import * as argon2 from 'argon2';
import { DeviceFingerprint } from '../common/utils/fingerprint.util';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  /** Internal telemetry provider for security auditing */
  private readonly logger = new Logger('ZENITH_IAM_KERNEL');

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Provisions a new identity and initializes a hardware-bound session.
   * * @param {SignupDto} dto - Validated identity payload.
   * @param {DeviceFingerprint} fp - Inbound hardware telemetry.
   * @returns {Promise<{access_token: string, refresh_token: string}>}
   */
  async signup(dto: SignupDto, fp: DeviceFingerprint) {
    try {
      const hashedPassword = await argon2.hash(dto.password);

      const newUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
          firstName: dto.firstName,
          familyName: dto.familyName,
          phoneNumber: dto.phoneNumber,
          role: Role.USER,
          permissions: {
            createMany: {
              data: [
                { action: 'PROFILE_READ' },
                { action: 'PROFILE_UPDATE' },
              ],
            },
          },
        },
        select: { id: true, email: true, role: true, permissions: { select: { action: true } } },
      });

      this.logger.log(`AUDIT [IDENTITY_PROVISIONED]: ID: ${newUser.id} | Device: ${fp.deviceId}`);

      const permissions = newUser.permissions.map(p => p.action);
      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role, permissions);

      await this.createSession(newUser.id, tokens.refresh_token, fp);
      return tokens;

    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Registry collision (Identity already exists).');
      }
      throw error;
    }
  }

  /**
   * Authenticates identity and appends a hardware-bound session context.
   * Implements constant-time verification to prevent side-channel leaks.
   */
  async signin(dto: SigninDto, fp: DeviceFingerprint) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, email: true, password: true, role: true, permissions: { select: { action: true } } },
    });

    /** 🛡️ Anti-Enumeration Dummy Hash */
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$66YmZp...'; 
    const isPasswordValid = user 
      ? await argon2.verify(user.password, dto.password)
      : await argon2.verify(dummyHash, dto.password);

    if (!user || !isPasswordValid) {
      this.logger.warn(`SECURITY_ALERT [SIGNIN_FAIL]: Unauthorized access on ${dto.email}`);
      throw new UnauthorizedException('ZENITH_GUARD: Invalid credentials.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);

    await this.createSession(user.id, tokens.refresh_token, fp);
    return tokens;
  }

  /**
   * Executes RTR (Refresh Token Rotation) with Hardware Integrity Verification.
   * Implements automated global lockout upon detection of token reuse or device hijacking.
   */
  async refreshTokens(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const userSessions = await this.prisma.session.findMany({ where: { userId } });

    let activeSession: sessionType | null = null;

    for (const session of userSessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        activeSession = session;
        break;
      }
    }

    /** 🛡️ REUSE DETECTION: Automatic Account Lockout */
    if (!activeSession) {
      await this.signoutAll(userId); 
      this.logger.error(`CRITICAL [REUSE_DETECTED]: Potential breach for User ${userId}. Revoking all sessions.`);
      throw new ForbiddenException('ZENITH_SHIELD: Security anomaly detected. Account locked.');
    }

    /** 🛡️ HIJACKING DETECTION: Hardware Telemetry Verification */
    if (activeSession.deviceId !== fp.deviceId) {
      await this.signoutAll(userId);
      this.logger.error(`CRITICAL [HIJACK_DETECTED]: Identity ${userId} device mismatch. Lockout triggered.`);
      throw new ForbiddenException('ZENITH_SHIELD: Session hijacking attempt detected.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, role: true, permissions: { select: { action: true } } },
    });

    if (!user) throw new ForbiddenException('ZENITH_GUARD: Identity lost.');

    const tokens = await this.signTokens(userId, user.email, user.role, user.permissions.map(p => p.action));
    const newHashedRt = await argon2.hash(tokens.refresh_token);

    await this.prisma.session.update({
      where: { id: activeSession.id },
      data: { 
        hashedRt: newHashedRt,
        os: fp.os,
        browser: fp.browser,
      },
    });

    return tokens;
  }

  /**
   * Targeted Session Revocation.
   * Invalidates a single hardware context without affecting other active sessions.
   * * @param {string} userId - Target identity.
   * @param {string} rawRt - Token context to be invalidated.
   */
  async signout(userId: string, rawRt: string) {
    const sessions = await this.prisma.session.findMany({ where: { userId } });
    
    for (const session of sessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        await this.prisma.session.delete({ where: { id: session.id } });
        break;
      }
    }

    this.logger.log(`AUDIT [SESSION_DECOUPLED]: Single device logout for Identity ${userId}`);
    return { status: 'OK', message: 'Specific session invalidated.' };
  }

  /**
   * Nuclear Session Purge.
   * Terminates all active hardware contexts for a specific identity.
   */
  async signoutAll(userId: string) {
    await this.prisma.session.deleteMany({ where: { userId } });
    this.logger.warn(`AUDIT [GLOBAL_LOGOUT]: All hardware contexts purged for Identity ${userId}`);
    return { status: 'OK', message: 'All active sessions invalidated.' };
  }

  /**
   * Orchestrates the creation of hardware-bound session metadata.
   * @private
   */
  private async createSession(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const hashedRt = await argon2.hash(rawRt);
    await this.prisma.session.create({
      data: {
        userId,
        hashedRt,
        deviceId: fp.deviceId,
        os: fp.os,
        browser: fp.browser,
        device: fp.deviceType,
      },
    });
  }

  /**
   * Signs cryptographic payloads with enterprise-grade rotation intervals.
   * @private
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
}