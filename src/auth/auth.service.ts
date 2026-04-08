import {
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

/**
 * ZENITH AUTHENTICATION SERVICE - CORE CRYPTO ENGINE
 * --------------------------------------------------
 * SECURITY ARCHITECTURE:
 * 1. RBAC Synchronization: Roles are fetched during signing to ensure token authority.
 * 2. Timing Attack Resilience: Dummy hashing for non-existent users.
 * 3. Token Rotation (RT): Implements hash-based refresh token verification.
 * 4. Salt Hardening: Standardized 12 rounds for PII, 10 for ephemeral RTs.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  /**
   * IDENTITY ESTABLISHMENT (SIGNUP)
   * @description Creates a secure user record and initiates the first authenticated session.
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
        },
      });

      this.logger.log(`[AUTH] Identity verified and established for: ${newUser.email}`);

      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role);
      await this.updateHashedRt(newUser.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      if (error.code === 'P2002') {
        this.logger.warn(`[AUTH] Registration conflict on existing credential.`);
        throw new ForbiddenException('Registration could not be completed.');
      }
      throw new ForbiddenException('System temporarily unavailable.');
    }
  }

  /**
   * SESSION INITIATION (SIGNIN)
   * @description Validates credentials with timing-attack mitigation and issues token pairs.
   */
  async signin(dto: SigninDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    const dummyHash = '$2b$12$L8v4Y0U6U7S8T9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O';
    const passwordToCompare = user ? user.password : dummyHash;
    const isPasswordValid = await bcrypt.compare(dto.password, passwordToCompare);

    if (!user || !isPasswordValid) {
      this.logger.warn(`[AUTH] Unauthorized access attempt detected.`);
      throw new UnauthorizedException('Invalid email or password.');
    }

    this.logger.log(`[AUTH] Access granted for User ID: ${user.id}`);

    const tokens = await this.signTokens(user.id, user.email, user.role);
    await this.updateHashedRt(user.id, tokens.refresh_token);
    return tokens;
  }

  /**
   * SESSION TERMINATION (SIGNOUT)
   * @description Nullifies the refresh token hash to prevent hijacked session reuse.
   */
  async signout(userId: number) {
    await this.prisma.user.updateMany({
      where: { id: userId, hashedRt: { not: null } },
      data: { hashedRt: null },
    });
    this.logger.log(`[AUTH] User session invalidated for ID: ${userId}`);
    return { status: 'success', message: 'Session revoked.' };
  }

  /**
   * TOKEN REFRESH PROTOCOL
   * @description Rotates the access token after verifying the refresh token's hash integrity.
   */
  async refreshTokens(userId: number, rawRt: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied: No active session.');

    const isRtValid = await bcrypt.compare(rawRt, user.hashedRt);
    if (!isRtValid) {
      this.logger.error(`[AUTH] Potential Token Theft Attempt - User ID: ${userId}`);
      throw new ForbiddenException('Access Denied: Compromised Token.');
    }

    const tokens = await this.signTokens(user.id, user.email, user.role);
    await this.updateHashedRt(user.id, tokens.refresh_token);
    return tokens;
  }

  /**
   * JWT COMPOSITION ENGINE
   * @private
   */
  private async signTokens(userId: number, email: string, role: string) {
    const jwtPayload = { sub: userId, email, role };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(jwtPayload, {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwt.signAsync(jwtPayload, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return { access_token: accessToken, refresh_token: refreshToken };
  }

  private async updateHashedRt(userId: number, rawRt: string) {
    const hashedRt = await bcrypt.hash(rawRt, 10);
    await this.prisma.user.update({ where: { id: userId }, data: { hashedRt } });
  }
}