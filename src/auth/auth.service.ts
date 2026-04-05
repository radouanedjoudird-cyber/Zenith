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
 * ZENITH SECURE AUTH SERVICE
 * SECURITY STRATEGY:
 * 1. Constant Time Responses: Mitigation against Timing Attacks.
 * 2. Error Masking: Generic exceptions to prevent account enumeration.
 * 3. Hash Hardening: 12 salt rounds for password, 10 for refresh token.
 * 4. Token Rotation: Every refresh issues a brand new token pair.
 * 5. Token Revocation: Signing out destroys the refresh token in the database.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  // ─────────────────────────────────────────────
  // SIGNUP
  // ─────────────────────────────────────────────

  /**
   * SECURE SIGNUP:
   * Hashes the password before persisting, then issues a full token pair.
   * Generic error messages prevent attackers from detecting registered emails.
   */
  async signup(dto: SignupDto) {
    try {
      /**
       * HASH HARDENING:
       * 12 salt rounds is the current industry gold standard.
       * It balances security strength and server performance.
       */
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

      this.logger.log(`New user registered successfully.`);

      const tokens = await this.signTokens(newUser.id, newUser.email);
      await this.updateHashedRt(newUser.id, tokens.refresh_token);
      return tokens;

    } catch (error) {
      /**
       * SECURITY: P2002 Conflict
       * Instead of revealing "User already exists", we return a generic message.
       * This prevents attackers from bulk-checking registered emails (Enumeration Attack).
       */
      if (error.code === 'P2002') {
        this.logger.warn(`Signup conflict: Attempt with existing credential.`);
        throw new ForbiddenException('Registration could not be completed.');
      }

      this.logger.error('Critical Signup Error', error.stack);
      throw new ForbiddenException('System temporarily unavailable.');
    }
  }

  // ─────────────────────────────────────────────
  // SIGNIN
  // ─────────────────────────────────────────────

  /**
   * SECURE SIGNIN:
   * Implements "Ghost Comparison" technique to fight Timing Attacks.
   * Issues a full token pair on success and stores the hashed refresh token.
   */
  async signin(dto: SigninDto) {
    const GENERIC_ERROR = 'Invalid email or password.';

    // 1. Fetch user by email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    /**
     * TIMING ATTACK PROTECTION (Ghost Comparison):
     * Even if the user does not exist, we MUST perform a bcrypt comparison
     * using a dummy hash. This ensures the server response time is always
     * identical, preventing attackers from detecting valid emails via timing.
     */
    const dummyHash = '$2b$12$L8v4Y0U6U7S8T9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O';
    const passwordToCompare = user ? user.password : dummyHash;
    const isPasswordValid = await bcrypt.compare(dto.password, passwordToCompare);

    /**
     * UNIFORM RESPONSE:
     * Both conditions are checked together and throw the same generic error.
     * This prevents attackers from distinguishing between wrong email and wrong password.
     */
    if (!user || !isPasswordValid) {
      this.logger.warn(`Unauthorized login attempt detected.`);
      throw new UnauthorizedException(GENERIC_ERROR);
    }

    this.logger.log(`User session started.`);

    const tokens = await this.signTokens(user.id, user.email);
    await this.updateHashedRt(user.id, tokens.refresh_token);
    return tokens;
  }

  // ─────────────────────────────────────────────
  // SIGNOUT
  // ─────────────────────────────────────────────

  /**
   * SECURE SIGNOUT (Token Revocation):
   * Sets hashedRt to null in the database, immediately invalidating
   * the refresh token. Even if an attacker stole the token, it becomes
   * completely useless after this operation.
   */
  async signout(userId: number) {
    /**
     * SECURITY: We use updateMany with a condition to ensure we only
     * nullify tokens for users who actually have an active session.
     * This prevents unnecessary database writes.
     */
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: { not: null },
      },
      data: { hashedRt: null },
    });

    this.logger.log(`User ID ${userId} signed out. Refresh token revoked.`);
    return { message: 'Signed out successfully.' };
  }

  // ─────────────────────────────────────────────
  // REFRESH
  // ─────────────────────────────────────────────

  /**
   * SECURE TOKEN REFRESH (Token Rotation):
   * Validates the incoming refresh token against the stored hash.
   * On success, issues a brand new token PAIR and rotates the stored hash.
   * The old refresh token is immediately invalidated — it can never be reused.
   */
  async refreshTokens(userId: number, rawRt: string) {
    // 1. Find the user and ensure they have an active session
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.hashedRt) {
      this.logger.warn(`Refresh attempt for inactive session. User ID: ${userId}`);
      throw new ForbiddenException('Access Denied. No active session found.');
    }

    /**
     * TOKEN VALIDATION:
     * We compare the raw incoming token against the stored bcrypt hash.
     * This is the core security check — if this fails, the token is invalid or stolen.
     */
    const isRtValid = await bcrypt.compare(rawRt, user.hashedRt);
    if (!isRtValid) {
      this.logger.warn(`Invalid refresh token detected. User ID: ${userId}`);
      throw new ForbiddenException('Access Denied. Token validation failed.');
    }

    /**
     * TOKEN ROTATION:
     * We issue a completely new token pair and update the stored hash.
     * The old refresh token is now invalid — single-use enforcement.
     */
    this.logger.log(`Token rotation successful for User ID: ${userId}`);
    const tokens = await this.signTokens(user.id, user.email);
    await this.updateHashedRt(user.id, tokens.refresh_token);
    return tokens;
  }

  // ─────────────────────────────────────────────
  // PRIVATE HELPERS
  // ─────────────────────────────────────────────

  /**
   * DUAL TOKEN SIGNING:
   * Issues both an access_token (short-lived) and a refresh_token (long-lived).
   * Two separate secrets are used to prevent token type confusion attacks —
   * a refresh token cannot be used as an access token and vice versa.
   */
  private async signTokens(
    userId: number,
    email: string,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const payload = { sub: userId, email };

    const [accessToken, refreshToken] = await Promise.all([
      /**
       * ACCESS TOKEN:
       * Short lifespan (15 minutes) minimizes the damage window
       * if the token is ever intercepted or stolen.
       */
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: '15m',
      }),

      /**
       * REFRESH TOKEN:
       * Long lifespan (7 days) for seamless user experience.
       * Uses a completely separate secret to prevent token type confusion.
       */
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  /**
   * SECURE REFRESH TOKEN STORAGE:
   * We NEVER store the raw refresh token in the database.
   * Only a bcrypt hash is persisted — 10 rounds is sufficient here
   * because refresh tokens are already long random strings (not user passwords).
   */
  private async updateHashedRt(userId: number, rawRt: string): Promise<void> {
    const hashedRt = await bcrypt.hash(rawRt, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt },
    });
  }
}