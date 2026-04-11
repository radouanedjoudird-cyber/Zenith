import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';
import { Permissions } from '../common/decorators/permissions.decorator';
import { Public } from '../common/decorators/public.decorator';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { RtGuard } from './guards/rt.guard';

/**
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) GATEWAY - v4.0
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * CORE SECURITY PRINCIPLES:
 * 1. DEFENSE_IN_DEPTH: Layered validation (Throttling -> Guard -> Kernel Logic).
 * 2. RTR_ENFORCEMENT: Strictly controls the 'Burn-on-Use' rotation lifecycle.
 * 3. FORENSIC_TELEMETRY: Comprehensive logging for audit readiness.
 * 4. PERFORMANCE: Optimized RTT for stateless session audits.
 */
@ApiTags('Identity & Access Management')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger('Zenith-Auth-Controller');

  constructor(private readonly authService: AuthService) {}

  /**
   * IDENTITY PROVISIONING (SIGNUP)
   * ------------------------------
   * Registers a new subject. Protected by restrictive throttling to prevent
   * automated registry exhaustion.
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // Anti-Spam: 5 requests per minute
  @Post('signup')
  @ApiOperation({ summary: 'Identity Provisioning (Signup)' })
  @ApiResponse({ status: 201, description: 'Identity registry established successfully.' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log(`🚀 [AUTH_INGRESS] Initiating provisioning for: ${signupDto.email}`);
    return await this.authService.signup(signupDto);
  }

  /**
   * SESSION AUTHENTICATION (SIGNIN)
   * -------------------------------
   * Authenticates credentials and initializes the rotation cycle.
   */
  @Public()
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // Anti-Brute: 10 attempts per minute
  @Post('signin')
  @ApiOperation({ summary: 'Session Authentication (Signin)' })
  @ApiResponse({ status: 200, description: 'Cryptographic identity tokens issued.' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`🔑 [AUTH_INGRESS] Authenticating identity: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  /**
   * CRYPTOGRAPHIC TOKEN ROTATION (REFRESH)
   * --------------------------------------
   * Logic: Executes the 'Burn-on-Use' protocol.
   * COMPLIANCE: Validates the RT signature and persisted rotation hash.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Token Rotation (Refresh)' })
  @ApiResponse({ status: 200, description: 'Rotation cycle complete. New tokens issued.' })
  @ApiResponse({ status: 403, description: 'SECURITY_BREACH: Potential token reuse detected.' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const userId = Number(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];

    this.logger.log(`🔄 [AUTH_ROTATION] Executing RTR cycle for ID: ${userId}`);
    return await this.authService.refreshTokens(userId, refreshToken);
  }

  /**
   * SESSION TERMINATION (SIGNOUT)
   * ------------------------------
   * Atomic revocation of the persistent session hash.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Session Termination (Signout)' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = Number(req.user?.['sub'] || req.user?.['id']);
    this.logger.log(`🚪 [AUTH_REVOKE] Invalidating session for ID: ${userId}`);
    return await this.authService.signout(userId);
  }

  /**
   * STATELESS SESSION AUDIT (STATUS)
   * --------------------------------
   * High-speed claim verification. Zero Database I/O.
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Stateless Session Audit (Status)' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = Number(req.user?.['sub'] || req.user?.['id']);
    this.logger.log(`📡 [AUTH_AUDIT] Telemetry request | Identity ID: ${userId}`);

    return {
      status: 'AUTHENTICATED_SECURE',
      timestamp: new Date().toISOString(),
      identity: {
        id: userId,
        email: req.user?.['email'],
        role: req.user?.['role'],
        permissions: req.user?.['permissions'],
      },
    };
  }
}