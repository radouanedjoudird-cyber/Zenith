import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Req,
  UseGuards
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { AtGuard } from './guards/at.guard';

/**
 * SECURE AUTH CONTROLLER
 * SECURITY STRATEGY:
 * 1. Strict Routing: Global prefix 'api' and versioning 'v1' are enforced in main.ts.
 * 2. Response Hardening: Avoid leaking server-side logic in JSON keys.
 * 3. Audit Logging: Trace authentication flow for security monitoring.
 */
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  /**
   * @Route   POST /auth/signup
   * @Desc    Secure User Registration
   * @Access  Public
   */
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log('Signup attempt received.');
    // The DTO transformation already sanitized the input before reaching here.
    return await this.authService.signup(signupDto);
  }

  /**
   * @Route   POST /auth/signin
   * @Desc    Secure User Authentication
   * @Access  Public
   */
  @Post('signin')
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`Signin attempt for: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  /**
   * @Route   GET /auth/status
   * @Desc    Check Session Integrity
   * @Access  Private (Protected by AtGuard)
   */
  @UseGuards(AtGuard)
  @Get('status')
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    /**
     * SECURITY: We only return essential user data.
     * req.user was already sanitized in JwtStrategy.validate()
     */
this.logger.log(`Status check passed for User ID: ${req.user?.['id']}`);    
    return {
      status: 'authenticated',
      timestamp: new Date().toISOString(),
      profile: req.user, 
    };
  }
}
