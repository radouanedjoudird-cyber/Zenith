import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

/**
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) - KERNEL v4.1 (MongoDB Edition)
 * -------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * CORE SECURITY IMPLEMENTATIONS:
 * 1. MIGRATION: Upgraded to String-based ObjectIDs for MongoDB compatibility.
 * 2. RTR (Refresh Token Rotation): Enforces single-use session integrity.
 * 3. CONSTANT_TIME_VERIFICATION: Guards against side-channel timing analysis.
 * 4. PBAC: Fine-grained permission mapping for distributed IoT ecosystems.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger('Zenith-Auth-Engine');

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  /**
   * IDENTITY PROVISIONING (SIGNUP)
   */
  async signup(dto: SignupDto) {
    try {
      const hashedPassword = await bcrypt.hash(dto.password, 12);

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
                { action: 'PROFILE_DELETE' },
              ],
            },
          },
        },
        select: { id: true, email: true, role: true, permissions: { select: { action: true } } },
      });

      this.logger.log(`✅ [AUTH_REGISTRY] Identity secured: ${newUser.email}`);

      const permissions = newUser.permissions.map(p => p.action);
      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role, permissions);

      await this.updateHashedRt(newUser.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('Zenith Security: Identity collision detected in registry.');
      }
      this.logger.error(`❌ [KERNEL_CRASH] Signup failure: ${error.message}`);
      throw error;
    }
  }

  /**
   * SESSION AUTHENTICATION (SIGNIN)
   */
  async signin(dto: SigninDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, email: true, password: true, role: true, permissions: { select: { action: true } } },
    });

    const dummyHash = '$2b$12$L8v4Y0U6U7S8T9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O';
    const isPasswordValid = await bcrypt.compare(dto.password, user?.password || dummyHash);

    if (!user || !isPasswordValid) {
      this.logger.warn(`⚠️ [AUTH_ALERT] Intrusion attempt detected on: ${dto.email}`);
      throw new UnauthorizedException('Zenith Guard: Authentication failed.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);

    await this.updateHashedRt(user.id, tokens.refresh_token);
    return tokens;
  }

  /**
   * REFRESH TOKEN ROTATION (RTR)
   */
  async refreshTokens(userId: string, rawRt: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, hashedRt: true, email: true, role: true, permissions: { select: { action: true } } },
    });

    if (!user || !user.hashedRt) {
      this.logger.warn(`🚨 [AUTH_REFUSED] Access to revoked session | ID: ${userId}`);
      throw new ForbiddenException('Zenith Guard: Session invalid or expired.');
    }

    const isRtValid = await bcrypt.compare(rawRt, user.hashedRt);

    if (!isRtValid) {
      await this.signout(userId);
      this.logger.error(`🚨 [CRITICAL_SECURITY] Token Reuse Detected! | ID: ${userId} | ACTION: LOCKOUT`);
      throw new ForbiddenException('Zenith Shield: Security breach detected. All sessions revoked.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);

    await this.updateHashedRt(user.id, tokens.refresh_token);

    this.logger.log(`🔄 [AUTH_ROTATION] Session rotated for ID: ${userId}`);
    return tokens;
  }

  /**
   * SESSION TERMINATION (SIGNOUT)
   */
  async signout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: null },
    });
    this.logger.log(`🚪 [AUTH_SESSION] Token invalidated for ID: ${userId}`);
    return { status: 'SUCCESS', message: 'Identity decoupled.' };
  }

  /**
   * JWT COMPOSITION ENGINE
   * FIX: Using explicit string literal for expiresIn to satisfy Type Overloads.
   */
  private async signTokens(userId: string, email: string, role: string, permissions: string[]) {
    const payload = { sub: userId, email, role, perms: permissions };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m', 
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d', 
      }),
    ]);

    return { access_token: accessToken, refresh_token: refreshToken };
  }

  /**
   * CRYPTOGRAPHIC PERSISTENCE
   */
  private async updateHashedRt(userId: string, rawRt: string) {
    const hashedRt = await bcrypt.hash(rawRt, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt },
    });
  }
}