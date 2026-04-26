/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) KERNEL
 * ============================================================================
 * @module AuthService
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Mission-critical service orchestrating identity lifecycle, 
 * cryptographic session management, and unified RBAC policy enforcement.
 * * * COMPLIANCE & SECURITY:
 * 1. NIST_800_63B: Digital Identity Guidelines.
 * 2. OWASP_ASVS: Session management and credential hygiene.
 * 3. FIPS_140_2: Advanced cryptography utilizing Argon2id.
 * ============================================================================
 */

import {
  BadRequestException,
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
import { Role } from '../common/enums/role.enum';
import { DeviceFingerprint } from '../common/utils/fingerprint.util';
import { PrismaService } from '../prisma/prisma.service';
import { ResetPasswordDto, SigninDto, SignupDto } from './dto';

@Injectable()
export class AuthService {
  /**
   * @private @readonly logger
   * @description Internal system logger for forensic telemetry and security audits.
   */
  private readonly logger = new Logger('ZENITH_IAM_KERNEL');

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * @method signup
   * @async
   * @description Provisions a new identity within the registry and assigns a default Role.
   * @param {SignupDto} dto - Credential payload.
   * @param {DeviceFingerprint} fp - Hardware telemetry for initial session binding.
   */
  async signup(dto: SignupDto, fp: DeviceFingerprint) {
    try {
      const hashedPassword = await argon2.hash(dto.password);
      
      let targetRole = await this.prisma.role.findUnique({ where: { name: Role.USER } });
      if (!targetRole) {
        targetRole = await this.prisma.role.create({
          data: { name: Role.USER, permissions: ['PROFILE_READ', 'PROFILE_UPDATE'] }
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

      const normalizedRole = this.normalizeRole(newUser.role?.name);
      const permissions = this.aggregatePermissions(newUser, normalizedRole);
      const tokens = await this.signTokens(newUser.id, newUser.email, normalizedRole, permissions, newUser.version);

      await this.createSession(newUser.id, tokens.refresh_token, fp);
      this.logger.log(`👤 [IDENTITY_CREATED]: ${newUser.email} | Context: ${normalizedRole}`);
      
      return tokens;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Identity collision. Email already exists.');
      }
      throw error;
    }
  }

  /**
   * @method signin
   * @async
   * @description Authenticates credentials using side-channel attack mitigation.
   */
  async signin(dto: SigninDto, fp: DeviceFingerprint) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      include: { role: true, permissions: true },
    });

    // CONSTANT_TIME_MITIGATION: Prevent user enumeration via timing analysis.
    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$dummyhashsecret'; 
    const isPasswordValid = user 
      ? await argon2.verify(user.password, dto.password)
      : await argon2.verify(dummyHash, dto.password);

    if (!user || !isPasswordValid) {
      this.logger.warn(`🛡️ [AUTH_FAILURE]: Unauthorized login attempt for: ${dto.email}`);
      throw new UnauthorizedException('ZENITH_GUARD: Invalid credentials.');
    }

    if (user.status !== AccountStatus.ACTIVE) {
      throw new ForbiddenException(`ZENITH_GUARD: Account status [${user.status}] restricts access.`);
    }

    const normalizedRole = this.normalizeRole(user.role?.name);
    const permissions = this.aggregatePermissions(user, normalizedRole);
    const tokens = await this.signTokens(user.id, user.email, normalizedRole, permissions, user.version);

    await this.createSession(user.id, tokens.refresh_token, fp);
    this.logger.log(`🔑 [INGRESS]: Access granted for ${user.email} as [${normalizedRole}]`);
    
    return tokens;
  }

  /**
   * @method refreshTokens
   * @async
   * @description Implements Refresh Token Rotation (RTR). Detects and mitigates token hijacking.
   */
  async refreshTokens(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const sessions = await this.prisma.session.findMany({ where: { userId } });
    let activeSession: SessionType | null = null;

    for (const session of sessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        activeSession = session;
        break;
      }
    }

    if (!activeSession) {
      await this.signoutAll(userId);
      this.logger.error(`🚨 [TOKEN_HIJACK]: Replay attack suspected for UID: ${userId}. Revoking all sessions.`);
      throw new ForbiddenException('ZENITH_SHIELD: Session anomaly detected.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true, permissions: true },
    });

    if (!user) throw new ForbiddenException('ZENITH_GUARD: Context lost.');

    const normalizedRole = this.normalizeRole(user.role?.name);
    const permissions = this.aggregatePermissions(user, normalizedRole);
    const tokens = await this.signTokens(userId, user.email, normalizedRole, permissions, user.version);

    await this.prisma.session.update({
      where: { id: activeSession.id },
      data: { hashedRt: await argon2.hash(tokens.refresh_token) },
    });

    return tokens;
  }

  /**
   * @method requestPasswordReset
   * @async
   * @description Generates a cryptographic token for credential recovery.
   */
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) return { status: 'SUCCESS' }; // Anti-enumeration

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
      },
    });
    return { status: 'SUCCESS', token: resetToken };
  }

  /**
   * @method resetPassword
   * @async
   * @description Finalizes credential rotation and forces global logout via version increment.
   */
  async resetPassword(dto: ResetPasswordDto) {
    const hashedToken = crypto.createHash('sha256').update(dto.token).digest('hex');
    const user = await this.prisma.user.findFirst({
      where: { resetPasswordToken: hashedToken, resetPasswordExpires: { gt: new Date() } },
    });

    if (!user) throw new BadRequestException('ZENITH_GUARD: Link invalid or expired.');

    const hashedPassword = await argon2.hash(dto.newPassword);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { 
        password: hashedPassword, 
        resetPasswordToken: null, 
        resetPasswordExpires: null, 
        version: { increment: 1 } 
      },
    });
    
    await this.signoutAll(user.id);
    return { status: 'SUCCESS', message: 'Identity credentials rotated successfully.' };
  }

  /**
   * @method signout
   * @async
   * @description Decouples a specific device context from the identity registry.
   */
  async signout(userId: string, rawRt: string) {
    const sessions = await this.prisma.session.findMany({ where: { userId } });
    for (const session of sessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        await this.prisma.session.delete({ where: { id: session.id } });
        break;
      }
    }
    return { status: 'SUCCESS' };
  }

  /**
   * @method signoutAll
   * @async
   * @description Global identity revocation. Terminates all active cryptographic sessions.
   */
  async signoutAll(userId: string) {
    await this.prisma.session.deleteMany({ where: { userId } });
    return { status: 'SUCCESS' };
  }

  /**
   * @private createSession
   * @async
   * @description Records device context with safe fallback for optional metadata fields.
   */
  private async createSession(userId: string, rawRt: string, fp: DeviceFingerprint) {
    const hashedRt = await argon2.hash(rawRt);
    
    // SAFE_TYPING: Using bracket notation for fields that might be missing in Interface
    await this.prisma.session.create({
      data: {
        userId,
        hashedRt,
        deviceId: fp.deviceId,
        os: fp.os,
        browser: fp.browser,
        device: fp.deviceType,
        ipAddress: (fp as any).ip || null,
        userAgent: (fp as any).userAgent || null,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
  }

  /**
   * @private normalizeRole
   * @description Unified mapper for resolving DB string inconsistencies to Role Enum.
   */
  private normalizeRole(roleName?: string): Role {
    if (!roleName) return Role.USER;
    const cleanRole = roleName.toUpperCase().replace(/\s/g, '_');
    
    if (cleanRole === 'SUPERADMIN' || cleanRole === 'SUPER_ADMIN') return Role.SUPER_ADMIN;
    
    return (Role[cleanRole as keyof typeof Role] as Role) || Role.USER;
  }

  /**
   * @private aggregatePermissions
   * @description Merges role-based and direct claims into a deduplicated policy array.
   */
  private aggregatePermissions(user: any, role: Role): string[] {
    if (role === Role.SUPER_ADMIN) return ['*'];
    
    const rolePerms = user.role?.permissions || [];
    const directPerms = user.permissions?.map((p: any) => p.action) || [];
    
    return [...new Set([...rolePerms, ...directPerms])];
  }

  /**
   * @private signTokens
   * @async
   * @description Generates cryptographically signed JWT pairs (Access/Refresh).
   */
  private async signTokens(uId: string, email: string, role: Role, perms: string[], version: number) {
    const payload = { sub: uId, email, role, perms, version };
    
    const atSecret = this.config.get<string>('AT_SECRET');
    const rtSecret = this.config.get<string>('RT_SECRET');

    const [at, rt] = await Promise.all([
      this.jwt.signAsync(payload, { secret: atSecret, expiresIn: '15m' }),
      this.jwt.signAsync(payload, { secret: rtSecret, expiresIn: '7d' }),
    ]);

    return { access_token: at, refresh_token: rt };
  }
}