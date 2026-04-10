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
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) - KERNEL v4.0
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * SECURITY PROTOCOLS ENFORCED:
 * 1. RTR (Refresh Token Rotation): Implements 'Burn-on-Use' to prevent replay attacks.
 * 2. ATOMIC_REVOCATION: Immediate session invalidation upon breach detection.
 * 3. CONSTANT_TIME_VERIFICATION: Mitigates side-channel timing attacks during auth.
 * 4. PBAC (Permission-Based Access Control): Granular identity provisioning.
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
   * ------------------------------
   * Registers a new identity with a Work Factor of 12 for high entropy.
   * Initializes default PBAC permissions for the USER role.
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
   * -------------------------------
   * Authenticates identity and initializes the cryptographic rotation cycle.
   * Implements anti-enumeration logic via constant-time comparison.
   */
  async signin(dto: SigninDto) {
    const user = await this.prisma.user.findUnique({ 
      where: { email: dto.email },
      select: { id: true, email: true, password: true, role: true, permissions: { select: { action: true } } } 
    });

    // ANTI-ENUMERATION: Prevents timing attacks by simulating a hash check even if user doesn't exist.
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
   * SESSION TERMINATION (SIGNOUT)
   * -----------------------------
   * Atomic cleanup of the rotation hash to ensure immediate session death.
   */
  async signout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: null },
    });
    this.logger.log(`🚪 [AUTH_SESSION] Token invalidated for ID: ${userId}`);
    return { status: 'SUCCESS', message: 'Identity decoupled.' };
  }

  /**
   * REFRESH TOKEN ROTATION (RTR) - INTRUSION PREVENTION SYSTEM
   * ----------------------------------------------------------
   * Detects token reuse (stolen tokens) and triggers a nuclear revocation.
   * This is the critical shield that returns 403 Forbidden on reuse.
   */
  async refreshTokens(userId: number, rawRt: string) {
    // PHASE 1: Latency-Optimized Hydration
    const user = await this.prisma.user.findUnique({ 
      where: { id: userId },
      select: { hashedRt: true, email: true, role: true, id: true, permissions: { select: { action: true } } }
    });
    
    // PHASE 2: Zero-Trust Verification
    if (!user || !user.hashedRt) {
      this.logger.warn(`🚨 [AUTH_REFUSED] Access to revoked session | ID: ${userId}`);
      throw new ForbiddenException('Zenith Security: Session invalid or expired.');
    }

    // PHASE 3: Cryptographic Match (The Breach Detector)
    const isRtValid = await bcrypt.compare(rawRt, user.hashedRt);

    if (!isRtValid) {
      // ATOMIC REVOCATION: Wipe all sessions for this user due to suspected theft.
      await this.prisma.user.update({
        where: { id: userId },
        data: { hashedRt: null }, 
      });

      this.logger.error(`🚨 [CRITICAL_SECURITY] Token Reuse Detected! | ID: ${userId} | ACTION: LOCKOUT`);
      throw new ForbiddenException('Zenith Shield: Security breach detected. All sessions revoked.');
    }

    // PHASE 4: Credential Rotation
    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);
    
    // PHASE 5: Persistence Commit
    await this.updateHashedRt(user.id, tokens.refresh_token);
    
    this.logger.log(`🔄 [AUTH_ROTATION] Session rotated for ID: ${userId}`);
    return tokens;
  }

  /**
   * JWT COMPOSITION ENGINE
   * ----------------------
   * Generates short-lived access tokens and long-lived rotation tokens.
   */
  private async signTokens(userId: number, email: string, role: string, permissions: string[]) {
    const payload = { sub: userId, email, role, perms: permissions };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: '15m', 
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d', 
      }),
    ]);

    return { access_token: accessToken, refresh_token: refreshToken };
  }

  /**
   * CRYPTOGRAPHIC PERSISTENCE
   * -------------------------
   * Safely hashes the rotation token using a balanced work factor (10).
   */
  private async updateHashedRt(userId: number, rawRt: string) {
    const salt = await bcrypt.genSalt(10);
    const hashedRt = await bcrypt.hash(rawRt, salt);
    
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt },
    });
    
    this.logger.debug(`🔐 [AUTH_PERSISTENCE] RT Hash rotated for ID: ${userId}`);
  }
}