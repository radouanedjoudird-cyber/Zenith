import {
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Role } from '../common/enums/role.enum';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

/**
 * ZENITH AUTHENTICATION & IDENTITY SERVICE
 * -----------------------------------------
 * CORE RESPONSIBILITIES:
 * - Secure Identity Provisioning (Signup)
 * - Anti-Escalation Role Filtering (RBAC Safety)
 * - Multi-Factor Session Issuance (JWT AT/RT)
 * - Timing Attack Mitigation (Signin)
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
   * IDENTITY PROVISIONING (SIGNUP)
   * ------------------------------
   * @logic Implements 'The Defensive Default' - Users cannot escalate their own 
   * privileges via public endpoints. Requests for ADMIN/MODERATOR are forcefully 
   * downgraded to USER unless created via an authorized administrative channel.
   * * @audit_update Includes the 'id' in the response to ensure the AuditInterceptor 
   * captures the exact entity identifier for the forensic trail.
   */
  async signup(dto: SignupDto) {
    try {
      const hashedPassword = await bcrypt.hash(dto.password, 12);

      // SECURITY SHIELD: Detects and mitigates Privilege Escalation attempts
      let finalRole: Role = Role.USER;
      
      if (dto.role && dto.role !== Role.USER) {
        this.logger.warn(
          `[SECURITY ALERT] Privilege Escalation Attempt: ${dto.email} requested ${dto.role}. Logic forced to USER.`
        );
        finalRole = Role.USER; 
      }

      const newUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
          firstName: dto.firstName,
          familyName: dto.familyName,
          phoneNumber: dto.phoneNumber,
          role: finalRole,
        },
      });

      this.logger.log(`[AUTH] Identity Secured: ${newUser.email} | Assigned Role: ${newUser.role}`);

      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role);
      await this.updateHashedRt(newUser.id, tokens.refresh_token);

      /**
       * @return Full authentication payload including the user ID to facilitate 
       * deep auditing and entity resolution by the monitoring middleware.
       */
      return {
        ...tokens,
        id: newUser.id,
      };
    } catch (error) {
      if (error.code === 'P2002') {
        this.logger.error(`[AUTH] Conflict: Identity ${dto.email} already exists.`);
        throw new ForbiddenException('Registration could not be completed.');
      }
      throw new ForbiddenException('Identity Engine Timeout.');
    }
  }

  /**
   * SESSION AUTHENTICATION (SIGNIN)
   * -------------------------------
   * @logic Utilizes constant-time comparison (mitigating timing attacks) and
   * fetches fresh role claims from the DB to prevent stale session privileges.
   */
  async signin(dto: SigninDto) {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });

    // SECURITY: Comparison against dummy hash if user not found to prevent user enumeration
    const dummyHash = '$2b$12$L8v4Y0U6U7S8T9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O';
    const passwordToCompare = user ? user.password : dummyHash;
    const isPasswordValid = await bcrypt.compare(dto.password, passwordToCompare);

    if (!user || !isPasswordValid) {
      this.logger.warn(`[AUTH] Unauthorized Access Attempt on account: ${dto.email}`);
      throw new UnauthorizedException('Invalid credentials.');
    }

    this.logger.log(`[AUTH] Session Initialized for Identity: ${user.id}`);

    const tokens = await this.signTokens(user.id, user.email, user.role);
    await this.updateHashedRt(user.id, tokens.refresh_token);

    // Provide User ID in response for frontend context and backend auditing
    return {
      ...tokens,
      id: user.id,
    };
  }

  /**
   * SESSION TERMINATION (SIGNOUT)
   * -----------------------------
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
   * ----------------------
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
    
    return {
      ...tokens,
      id: user.id,
    };
  }

  /**
   * JWT COMPOSITION ENGINE
   * @private Generates cryptographically signed Access & Refresh tokens.
   */
  private async signTokens(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };

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
   * REFRESH TOKEN HASH PERSISTENCE
   * @private Updates the hashed RT in database for rotation security.
   */
  private async updateHashedRt(userId: number, rawRt: string) {
    const hashedRt = await bcrypt.hash(rawRt, 10);
    await this.prisma.user.update({ where: { id: userId }, data: { hashedRt } });
  }
}