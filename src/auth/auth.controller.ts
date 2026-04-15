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
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) GATEWAY - ENTERPRISE v5.0
 * ----------------------------------------------------------------------------
 * @class AuthController
 * @description Ingress point for multi-device session orchestration and identity provisioning.
 * * * ARCHITECTURAL STANDARDS:
 * 1. MULTI_TENANT_READY: Optimized for distributed session isolation.
 * 2. TELEMETRY_DRIVEN: Granular logging for forensic identity auditing.
 * 3. RATE_LIMITING: Enhanced defense against brute-force & credential stuffing.
 */
@ApiTags('Identity & Access Management')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger('ZENITH_AUTH_GATEWAY');

  constructor(private readonly authService: AuthService) {}

  /**
   * @method signup
   * @description Initiates identity provisioning and establishes the primary session.
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('signup')
  @ApiOperation({ summary: 'Identity Provisioning (Signup)' })
  @ApiResponse({ status: 201, description: 'Identity successfully provisioned in the registry.' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log(`🚀 [IDENTITY_PROVISIONING] Establishing context for: ${signupDto.email}`);
    return await this.authService.signup(signupDto);
  }

  /**
   * @method signin
   * @description Authenticates credentials and appends a new device context to the session registry.
   */
  @Public()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('signin')
  @ApiOperation({ summary: 'Session Authentication (Signin)' })
  @ApiResponse({ status: 200, description: 'New cryptographic session context initialized.' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`🔑 [INGRESS_AUTHENTICATION] Identity verification for: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  /**
   * @method refresh
   * @description Executes Refresh Token Rotation (RTR). 
   * Validates device-specific tokens and detects cross-device reuse anomalies.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Token Rotation (Refresh)' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];

    this.logger.log(`🔄 [SESSION_ROTATION] Executing RTR for Identity: ${userId}`);
    return await this.authService.refreshTokens(userId, refreshToken);
  }

  /**
   * @method signout
   * @description Targeted Session Revocation. Terminates only the current device's context.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Targeted Session Termination (Single Device)' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];
    
    this.logger.log(`🚪 [SESSION_REVOCATION] Decoupling specific device context for: ${userId}`);
    return await this.authService.signout(userId, refreshToken);
  }

  /**
   * @method signoutAll
   * @description Global Identity Purge. Terminates all active sessions across all devices.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout-all')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Global Identity Termination (All Devices)' })
  @HttpCode(HttpStatus.OK)
  async signoutAll(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    
    this.logger.warn(`💀 [GLOBAL_PURGE] Executing nuclear logout for Identity: ${userId}`);
    return await this.authService.signoutAll(userId);
  }

  /**
   * @method getStatus
   * @description Real-time telemetry audit for the current authenticated context.
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Stateless Session Telemetry (Status)' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    this.logger.debug(`📡 [TELEMETRY_AUDIT] Ingress telemetry request for: ${userId}`);

    return {
      status: 'IDENTITY_VERIFIED_SECURE',
      infrastructure: 'ZENITH_CLOUD_ENGINE_V5',
      timestamp: new Date().toISOString(),
      context: {
        id: userId,
        email: req.user?.['email'],
        role: req.user?.['role'],
        permissions: req.user?.['permissions'],
      },
    };
  }
}