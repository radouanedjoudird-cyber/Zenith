/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) GATEWAY
 * ============================================================================
 * @module AuthController
 * @version 7.4.0
 * @package @zenith/core-identity
 * @description 
 * Essential Ingress Gateway for managing identity lifecycles. Implements 
 * hardware-anchored session security and anti-enumeration recovery protocols.
 * * DESIGN SPECIFICATIONS:
 * 1. FORENSIC_TELEMETRY: Binds sessions to device-specific fingerprints.
 * 2. RTR_PROTOCOL: Implements Refresh Token Rotation for session integrity.
 * 3. INGRESS_VALIDATION: Strict DTO-based payload verification.
 * ============================================================================
 */

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
  UseInterceptors,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';

// ZENITH CORE IMPORTS
import { Permissions } from '../common/decorators/permissions.decorator';
import { Public } from '../common/decorators/public.decorator';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { AuditInterceptor } from '../common/interceptors/audit.interceptor';
import { DeviceFingerprint, FingerprintEngine } from '../common/utils/fingerprint.util';
import { AuthService } from './auth.service';

/**
 * IMPORTING UNIFIED IDENTITY DTOS
 * Using the Zenith Modular DTO Pattern for ingress validation.
 */
import {
  RequestRecoveryDto,
  ResetPasswordDto,
  SigninDto,
  SignupDto
} from './dto';

import { RtGuard } from './guards/rt.guard';

@ApiTags('Identity & Access Management')
@Controller('auth')
@UseInterceptors(AuditInterceptor)
export class AuthController {
  private readonly logger = new Logger('ZENITH_AUTH_GATEWAY');

  /**
   * @constructor
   * @param {AuthService} authService - Core authentication logic engine.
   */
  constructor(private readonly authService: AuthService) {}

  /**
   * @route POST /api/v1/auth/signup
   * @operation IDENTITY_PROVISIONING
   * @description Initiates a new identity registry and binds initial hardware context.
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('signup')
  @ApiOperation({ summary: 'Identity Provisioning (Signup)' })
  @ApiResponse({ status: 201, description: 'Identity successfully provisioned.' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto, @Req() req: Request): Promise<any> {
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');
    this.logger.log(`🚀 [PROVISIONING] Identity context initiated: ${signupDto.email}`);
    
    return await this.authService.signup(signupDto, fp);
  }

  /**
   * @route POST /api/v1/auth/signin
   * @operation SECURE_INGRESS
   * @description Validates credentials and generates a device-anchored session context.
   */
  @Public()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('signin')
  @ApiOperation({ summary: 'Hardware-Bound Authentication (Signin)' })
  @ApiResponse({ status: 200, description: 'Authentication validated.' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto, @Req() req: Request): Promise<any> {
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');
    this.logger.log(`🔑 [INGRESS] Identity verification triggered: ${signinDto.email}`);
    
    return await this.authService.signin(signinDto, fp);
  }

  /**
   * @route POST /api/v1/auth/recovery/request
   * @operation RECOVERY_SIGNALING
   * @description Triggers the secure account recovery protocol with anti-enumeration logic.
   */
  @Public()
  @Throttle({ default: { limit: 3, ttl: 3600000 } })
  @Post('recovery/request')
  @ApiOperation({ summary: 'Initiate Secure Identity Recovery' })
  @ApiResponse({ status: 200, description: 'Recovery protocol successfully initiated.' })
  @HttpCode(HttpStatus.OK)
  async requestRecovery(@Body() recoveryDto: RequestRecoveryDto): Promise<any> {
    this.logger.warn(`🛡️ [RECOVERY_INIT] RTR signaling for: ${recoveryDto.email}`);
    return await this.authService.requestPasswordReset(recoveryDto.email);
  }

  /**
   * @route POST /api/v1/auth/recovery/reset
   * @operation CREDENTIAL_ROTATION
   * @description Finalizes the recovery lifecycle by committing new credentials via token validation.
   * @param {ResetPasswordDto} resetDto - Cryptographic token and new entropy.
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 3600000 } })
  @Post('recovery/reset')
  @ApiOperation({ summary: 'Finalize Identity Recovery (Password Reset)' })
  @ApiResponse({ status: 200, description: 'Credentials successfully rotated.' })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetDto: ResetPasswordDto): Promise<any> {
    this.logger.log(`🛠️ [RECOVERY_COMMIT] Attempting credential rotation via cryptographic token.`);
    return await this.authService.resetPassword(resetDto);
  }

  /**
   * @route POST /api/v1/auth/refresh
   * @operation CRYPTOGRAPHIC_ROTATION
   * @description Executes RTR (Refresh Token Rotation) with forensic integrity checks.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Rotation (RTR)' })
  @ApiResponse({ status: 200, description: 'Session entropy successfully rotated.' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request): Promise<any> {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');

    this.logger.log(`🔄 [ROTATION] Validating hardware integrity for: ${userId}`);
    return await this.authService.refreshTokens(userId, refreshToken, fp);
  }

  /**
   * @route POST /api/v1/auth/signout
   * @operation SESSION_REVOCATION
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Targeted Session Revocation' })
  @ApiResponse({ status: 200, description: 'Hardware context successfully decoupled.' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request): Promise<any> {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];
    
    this.logger.log(`🚪 [REVOCATION] Decoupling hardware context for: ${userId}`);
    return await this.authService.signout(userId, refreshToken);
  }

  /**
   * @route GET /api/v1/auth/status
   * @operation TELEMETRY_EXPOSURE
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Identity Telemetry Status' })
  @ApiResponse({ status: 200, description: 'Telemetry data successfully retrieved.' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request): Promise<any> {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    
    return {
      status: 'IDENTITY_VERIFIED_SECURE',
      infrastructure: 'ZENITH_CORE_V7_DYNAMIC',
      timestamp: new Date().toISOString(),
      telemetry: {
        id: userId,
        email: req.user?.['email'],
        role: req.user?.['role'],
        assigned_permissions: req.user?.['perms'] || [],
      },
    };
  }
}