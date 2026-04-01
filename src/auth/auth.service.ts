import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { SigninDto, SignupDto } from './dto';

/**
 * ZENITH SECURE AUTH SERVICE
 * * SECURITY STRATEGY:
 * 1. Constant Time Responses: Mitigation against Timing Attacks.
 * 2. Error Masking: Generic exceptions to prevent account enumeration.
 * 3. Hash Hardening: Using 12 salt rounds for superior protection.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  /**
   * SECURE SIGNUP
   * Protects database schema and user existence details.
   */
  async signup(dto: SignupDto) {
    try {
      // 1. INCREASED HASH ROUNDS: 12 is the current industry gold standard.
      const hashedPassword = await bcrypt.hash(dto.password, 12);

      const newUser = await this.prisma.user.create({
        data: {
          email: dto.email, // Already normalized in DTO
          password: hashedPassword,
          firstName: dto.firstName,
          familyName: dto.familyName,
          phoneNumber: dto.phoneNumber,
        },
      });

      this.logger.log(`New user registered successfully.`);
      return this.signToken(newUser.id, newUser.email);

    } catch (error) {
      /**
       * SECURITY: P2002 Conflict
       * Instead of "User exists", we return a generic "Registration failed".
       * This prevents attackers from bulk-checking emails.
       */
      if (error.code === 'P2002') {
        this.logger.warn(`Signup conflict: Attempt with existing email.`);
        throw new ForbiddenException('Registration could not be completed.');
      }
      
      this.logger.error('Critical Signup Error', error.stack);
      throw new InternalServerErrorException('System temporarily unavailable.');
    }
  }

  /**
   * SECURE SIGNIN
   * Implements "Ghost Comparison" to fight Timing Attacks.
   */
  async signin(dto: SigninDto) {
    const GENERIC_ERROR = 'Invalid email or password.';

    // 1. Fetch user
    const user = await this.prisma.user.findUnique({ 
      where: { email: dto.email } 
    });

    /**
     * 2. TIMING ATTACK PROTECTION:
     * Even if the user doesn't exist, we MUST perform a bcrypt comparison.
     * We use a "dummy hash" to ensure the server response time is always the same.
     */
    const dummyHash = '$2b$12$L8v4Y0U6U7S8T9V0W1X2Y3Z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O';
    const passwordToCompare = user ? user.password : dummyHash;
    const isPasswordValid = await bcrypt.compare(dto.password, passwordToCompare);
    
    // 3. Uniform Response
    if (!user || !isPasswordValid) {
      this.logger.warn(`Unauthorized login attempt detected.`);
      throw new UnauthorizedException(GENERIC_ERROR);
    }

    this.logger.log(`User session started.`);
    return this.signToken(user.id, user.email);
  }

  /**
   * SECURE TOKEN SIGNING
   */
  private async signToken(userId: number, email: string): Promise<{ access_token: string }> {
    const payload = { sub: userId, email };
    
    // SECURITY: Absolute requirement for JWT_SECRET in environment variables.
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      this.logger.error('CRITICAL: JWT_SECRET is not defined in environment variables!');
      throw new InternalServerErrorException('Security Configuration Error.');
    }

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '1h',
      secret: secret,
    });

    return { access_token: token };
  }
}