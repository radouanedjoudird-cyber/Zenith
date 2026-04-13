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
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) GATEWAY - v4.1 (MongoDB Optimized)
 * ----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * CORE SECURITY PRINCIPLES:
 * 1. DEFENSE_IN_DEPTH: Layered validation (Throttling -> Guard -> Kernel Logic).
 * 2. RTR_ENFORCEMENT: Strictly controls the 'Burn-on-Use' rotation lifecycle.
 * 3. MIGRATION_READY: Refactored for String-based BSON ObjectIDs.
 * 4. PERFORMANCE: Optimized RTT for stateless session audits.
 */
@ApiTags('Identity & Access Management')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger('Zenith-Auth-Controller');

  constructor(private readonly authService: AuthService) {}

  /**
   * IDENTITY PROVISIONING (SIGNUP)
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
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
   */
  @Public()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
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
   * REFINED: userId is handled as String to comply with MongoDB ObjectId format.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Token Rotation (Refresh)' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    // SECURITY: Extracting identity from the payload as String (Not Number)
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];

    this.logger.log(`🔄 [AUTH_ROTATION] Executing RTR cycle for Identity: ${userId}`);
    return await this.authService.refreshTokens(userId, refreshToken);
  }

  /**
   * SESSION TERMINATION (SIGNOUT)
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Session Termination (Signout)' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    this.logger.log(`🚪 [AUTH_REVOKE] Invalidating session for Identity: ${userId}`);
    return await this.authService.signout(userId);
  }

  /**
   * STATELESS SESSION AUDIT (STATUS)
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Stateless Session Audit (Status)' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    this.logger.log(`📡 [AUTH_AUDIT] Telemetry request | Identity: ${userId}`);

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