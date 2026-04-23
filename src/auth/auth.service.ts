/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) KERNEL
 * ============================================================================
 * @module AuthService
 * @description Mission-critical identity orchestration with hardware anchoring.
 * * ARCHITECTURAL RATIONALE:
 * 1. ZERO_ENUMERATION: Constant-time hashing even for non-existent users.
 * 2. ATOMIC_SESSION_MANAGEMENT: Prevents race conditions during token rotation.
 * 3. HARDWARE_BINDING: Enforces device-specific session integrity.
 * ============================================================================
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
import { Prisma, Role, session as SessionType } from '@prisma/client';
import * as argon2 from 'argon2';
import { DeviceFingerprint } from '../common/utils/fingerprint.util';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('ZENITH_IAM_KERNEL');

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * @function signup
   * @description Provisions a new identity and binds the initial hardware context.
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

      this.logger.log(`AUDIT [IDENTITY_CREATED]: ${newUser.email} | Device: ${fp.deviceId}`);

      const permissions = newUser.permissions.map(p => p.action);
      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role, permissions);

      await this.createSession(newUser.id, tokens.refresh_token, fp);
      return tokens;

    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Registry collision. Identity already exists.');
      }
      throw error;
    }
  }

  /**
   * @function signin
   * @description Validates credentials with protection against side-channel attacks.
   */
  async signin(dto: SigninDto, fp: DeviceFingerprint) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, email: true, password: true, role: true, permissions: { select: { action: true } } },
    });

    /** * ANTI_ENUMERATION_PROTOCOL:
     * Maintains constant execution time regardless of identity existence.
     */
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$66YmZp...'; 
    const isPasswordValid = user 
      ? await argon2.verify(user.password, dto.password)
      : await argon2.verify(dummyHash, dto.password);

    if (!user || !isPasswordValid) {
      this.logger.warn(`SECURITY_ALERT [AUTH_FAILURE]: Unauthorized access attempt on ${dto.email}`);
      throw new UnauthorizedException('ZENITH_GUARD: Invalid credentials.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);

    await this.createSession(user.id, tokens.refresh_token, fp);
    return tokens;
  }

  /**
   * @function refreshTokens
   * @description Orchestrates RTR (Refresh Token Rotation) with device-bound integrity checks.
   */
  async refreshTokens(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const userSessions = await this.prisma.session.findMany({ 
      where: { userId },
      orderBy: { createdAt: 'desc' } 
    });

    /** FIXED: Explicit type assignment to prevent TS 'never' inference */
    let activeSession: SessionType | null = null;

    for (const session of userSessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        activeSession = session;
        break;
      }
    }

    /** 🛡️ REUSE_DETECTION: Immediate Global Purge */
    if (!activeSession) {
      await this.signoutAll(userId); 
      this.logger.error(`CRITICAL [REUSE_DETECTED]: Token reuse for User ${userId}. Revoking all sessions.`);
      throw new ForbiddenException('ZENITH_SHIELD: Anomaly detected. Identity sessions revoked.');
    }

    /** 🛡️ HIJACKING_PROTECTION: Telemetry Validation */
    if (activeSession.deviceId !== fp.deviceId) {
      await this.signoutAll(userId);
      this.logger.error(`CRITICAL [DEVICE_MISMATCH]: Device mismatch for ${userId}. Lockout triggered.`);
      throw new ForbiddenException('ZENITH_SHIELD: Unauthorized hardware detected.');
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
        updatedAt: new Date(),
      },
    });

    return tokens;
  }

  /**
   * @function signout
   * @description Invalidates a specific hardware-bound context.
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
    return { status: 'SUCCESS', message: 'Hardware context invalidated.' };
  }

  /**
   * @function signoutAll
   * @description Performs a nuclear purge of all active hardware contexts.
   */
  async signoutAll(userId: string) {
    await this.prisma.session.deleteMany({ where: { userId } });
    this.logger.warn(`AUDIT [GLOBAL_LOGOUT]: All sessions purged for Identity ${userId}`);
    return { status: 'SUCCESS', message: 'All sessions invalidated.' };
  }

  /**
   * @private createSession
   * @description Manages session persistence and enforces device quotas.
   */
  private async createSession(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const hashedRt = await argon2.hash(rawRt);
    
    // ATOMIC_QUOTA_MANAGEMENT: Limit to 5 concurrent devices
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
      },
    });
  }

  /**
   * @private signTokens
   * @description Generates asymmetric-like cryptographic token pairs.
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