/**
 * @fileoverview Authentication Ingress Gateway.
 * Manages identity lifecycle and hardware-bound session orchestration.
 * @version 6.0.0
 * @author Radouane Djoudi
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
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';
import { Permissions } from '../common/decorators/permissions.decorator';
import { Public } from '../common/decorators/public.decorator';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { AuditInterceptor } from '../common/interceptors/audit.interceptor';
import { DeviceFingerprint, FingerprintEngine } from '../common/utils/fingerprint.util';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { RtGuard } from './guards/rt.guard';

/**
 * AuthController acts as the primary gateway for identity challenges.
 * Implements hardware-anchored telemetry and cross-device anomaly detection.
 */
@ApiTags('Identity & Access Management')
@Controller('auth')
@UseInterceptors(AuditInterceptor) // 🛡️ Forensic tracing for every identity operation
export class AuthController {
  private readonly logger = new Logger('ZENITH_AUTH_GATEWAY');

  constructor(private readonly authService: AuthService) {}

  /**
   * Provisions a new identity and binds the initial hardware context.
   * @param signupDto - Identity payload.
   * @param req - Inbound HTTP request for telemetry extraction.
   */
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('signup')
  @ApiOperation({ summary: 'Identity Provisioning (Signup)' })
  @ApiResponse({ status: 201, description: 'Identity successfully provisioned and hardware-bound.' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto, @Req() req: Request) {
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');
    this.logger.log(`🚀 [PROVISIONING] Identity context initiated for: ${signupDto.email}`);
    
    return await this.authService.signup(signupDto, fp);
  }

  /**
   * Authenticates credentials and appends a hardware-bound session registry.
   */
  @Public()
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('signin')
  @ApiOperation({ summary: 'Hardware-Bound Authentication (Signin)' })
  @ApiResponse({ status: 200, description: 'Authentication successful. Device bound to session.' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto, @Req() req: Request) {
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');
    this.logger.log(`🔑 [INGRESS] Identity verification triggered for: ${signinDto.email}`);
    
    return await this.authService.signin(signinDto, fp);
  }

  /**
   * Executes Token Rotation with Hardware Integrity Checks.
   * Detects session hijacking if fingerprints do not match.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Rotation & Hijack Detection' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];
    
    // 🛡️ Critical: Re-generate fingerprint to verify hardware consistency
    const fp: DeviceFingerprint = FingerprintEngine.generate(req.get('user-agent') || '', req.ip || '127.0.0.1');

    this.logger.log(`🔄 [ROTATION] Executing RTR with Hardware Integrity Check for: ${userId}`);
    return await this.authService.refreshTokens(userId, refreshToken, fp);
  }

  /**
   * Targeted Session Revocation for specific device.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Targeted Session Termination' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    const refreshToken = req.user?.['refreshToken'];
    
    this.logger.log(`🚪 [REVOCATION] Invalidating session context for: ${userId}`);
    return await this.authService.signout(userId, refreshToken);
  }

  /**
   * Global Identity Purge across all hardware contexts.
   */
  @Public()
  @UseGuards(RtGuard)
  @Post('signout-all')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Global Hardware Purge (Nuclear Logout)' })
  @HttpCode(HttpStatus.OK)
  async signoutAll(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    
    this.logger.warn(`💀 [GLOBAL_PURGE] Executing nuclear session termination for: ${userId}`);
    return await this.authService.signoutAll(userId);
  }

  /**
   * Real-time Telemetry Status.
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'System Telemetry Audit' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = String(req.user?.['sub'] || req.user?.['id']);
    
    return {
      status: 'IDENTITY_VERIFIED_SECURE',
      infrastructure: 'ZENITH_CORE_V6_FORENSIC',
      node: process.env.HOSTNAME || 'ZENITH_PRIMARY',
      timestamp: new Date().toISOString(),
      context: {
        id: userId,
        email: req.user?.['email'],
        role: req.user?.['role'],
      },
    };
  }
}