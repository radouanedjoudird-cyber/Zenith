import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma, Role, Session } from '@prisma/client';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

/**
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) - ENTERPRISE KERNEL v5.1
 * -----------------------------------------------------------------------------
 * @class AuthService
 * @description Multi-device session orchestration with cross-device reuse detection.
 * * * ARCHITECTURAL STANDARDS:
 * 1. TYPE_SAFETY: Strict null checking and explicit interface enforcement.
 * 2. NUCLEAR_RECOIL: Global session revocation on single-token reuse detection.
 * 3. CRYPTOGRAPHY: Argon2id adaptive hashing (PHC Winner).
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger('ZENITH_AUTH_CORE');

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  /**
   * @method signup
   * @description Provisions a new identity and initializes the primary device session.
   */
  async signup(dto: SignupDto) {
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
                { action: 'PROFILE_DELETE' },
              ],
            },
          },
        },
        select: { id: true, email: true, role: true, permissions: { select: { action: true } } },
      });

      this.logger.log(`AUDIT [IDENTITY_PROVISIONED]: User ID: ${newUser.id}`);

      const permissions = newUser.permissions.map(p => p.action);
      const tokens = await this.signTokens(newUser.id, newUser.email, newUser.role, permissions);

      await this.createSession(newUser.id, tokens.refresh_token);
      return tokens;

    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('ZENITH_IAM: Registry collision detected.');
      }
      throw error;
    }
  }

  /**
   * @method signin
   * @description Authenticates credentials and appends a new session.
   */
  async signin(dto: SigninDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, email: true, password: true, role: true, permissions: { select: { action: true } } },
    });

    const dummyHash = '$argon2id$v=19$m=65536,t=3,p=4$66YmZp...'; 
    const isPasswordValid = user 
      ? await argon2.verify(user.password, dto.password)
      : await argon2.verify(dummyHash, dto.password);

    if (!user || !isPasswordValid) {
      this.logger.warn(`SECURITY_ALERT [SIGNIN_ATTEMPT]: Unauthorized target: ${dto.email}`);
      throw new UnauthorizedException('ZENITH_GUARD: Invalid credentials.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(user.id, user.email, user.role, permissions);

    await this.createSession(user.id, tokens.refresh_token);
    return tokens;
  }

  /**
   * @method refreshTokens
   * @description RTR with Multi-Device Reuse Detection.
   * FIXES: Resolved TS2322 (Type 'null'), TS18047 (Possibly null), and TS2339 (Property 'id').
   */
  async refreshTokens(userId: string, rawRt: string) {
    const userSessions = await this.prisma.session.findMany({
      where: { userId },
    });

    /**
     * 🟢 FIX TS2322: Explicitly typing the variable as Session | null.
     * Prevents the compiler from inferring 'null' as the only possible type.
     */
    let activeSession: Session | null = null;

    for (const session of userSessions) {
      const isMatch = await argon2.verify(session.hashedRt, rawRt);
      if (isMatch) {
        activeSession = session;
        break;
      }
    }

    /**
     * 🛡️ REUSE DETECTION PROTOCOL
     * If activeSession is still null after the loop, security compromise is suspected.
     */
    if (!activeSession) {
      await this.signoutAll(userId); 
      this.logger.error(`CRITICAL_ALERT [TOKEN_REUSE_DETECTED]: Potential breach for ID ${userId}.`);
      throw new ForbiddenException('ZENITH_SHIELD: Security anomaly detected. Global lockout engaged.');
    }

    // Provision new tokens
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, role: true, permissions: { select: { action: true } } },
    });

    /**
     * 🟢 FIX TS18047: Identity Context Verification.
     * Ensures the user still exists in the registry before accessing properties.
     */
    if (!user) {
      throw new ForbiddenException('ZENITH_GUARD: Identity context lost.');
    }

    const permissions = user.permissions.map(p => p.action);
    const tokens = await this.signTokens(userId, user.email, user.role, permissions);

    const newHashedRt = await argon2.hash(tokens.refresh_token);

    /**
     * 🟢 FIX TS2339: Compiler now knows activeSession is NOT null due to the guard above.
     */
    await this.prisma.session.update({
      where: { id: activeSession.id },
      data: { hashedRt: newHashedRt },
    });

    return tokens;
  }

  /**
   * @method signout
   */
  async signout(userId: string, rawRt: string) {
    const sessions = await this.prisma.session.findMany({ where: { userId } });
    
    for (const session of sessions) {
      if (await argon2.verify(session.hashedRt, rawRt)) {
        await this.prisma.session.delete({ where: { id: session.id } });
        break;
      }
    }

    this.logger.log(`AUDIT [SESSION_DECOUPLED]: Single device logout for ${userId}`);
    return { status: 'OK', message: 'Specific session invalidated.' };
  }

  /**
   * @method signoutAll
   */
  async signoutAll(userId: string) {
    await this.prisma.session.deleteMany({ where: { userId } });
    this.logger.warn(`AUDIT [GLOBAL_LOGOUT]: All sessions purged for Identity ${userId}`);
    return { status: 'OK', message: 'All active sessions invalidated.' };
  }

  /**
   * @private @method createSession
   */
  private async createSession(userId: string, rawRt: string) {
    const hashedRt = await argon2.hash(rawRt);
    await this.prisma.session.create({
      data: {
        userId,
        hashedRt,
      },
    });
  }

  /**
   * @private @method signTokens
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
}