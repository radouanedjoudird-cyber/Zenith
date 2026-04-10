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
 * @description Central orchestration for identity lifecycle, PBAC claims, and session security.
 * * CORE SECURITY PRINCIPLES:
 * 1. DEFENSE-IN-DEPTH: Layered validation (Throttling -> Guard -> Service Logic).
 * 2. RTR ENFORCEMENT: Strictly controls the Refresh Token Rotation lifecycle.
 * 3. TELEMETRY: Full logging of authentication state changes for audit readiness.
 * 4. ATOMICITY: Prevents partial session updates during cryptographic rotations.
 */
@ApiTags('Identity & Access Management')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger('Zenith-Auth-Controller');

  constructor(private readonly authService: AuthService) {}

  // ===========================================================================
  // SECTION: PUBLIC IDENTITY INGRESS
  // ===========================================================================

  /**
   * IDENTITY PROVISIONING (SIGNUP)
   * ------------------------------
   * Initiates a new user registry with baseline PBAC permissions.
   * Protected by specialized Rate-Limiting to mitigate account exhaustion attacks.
   */
  @Public() 
  @Throttle({ critical: { limit: 5, ttl: 60000 } }) 
  @Post('signup')
  @ApiOperation({ summary: 'Identity Provisioning (Signup)' })
  @ApiResponse({ status: 201, description: 'Identity registry established successfully.' })
  @ApiResponse({ status: 409, description: 'Identity collision: Email already exists.' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log(`🚀 [AUTH_INGRESS] Initiating provisioning for: ${signupDto.email}`);
    return await this.authService.signup(signupDto);
  }

  /**
   * SESSION AUTHENTICATION (SIGNIN)
   * -------------------------------
   * Validates credentials and issues high-entropy AT/RT pairs.
   * Leverages Anti-Enumeration logic within the kernel.
   */
  @Public() 
  @Throttle({ critical: { limit: 5, ttl: 60000 } }) 
  @Post('signin')
  @ApiOperation({ summary: 'Session Authentication (Signin)' })
  @ApiResponse({ status: 200, description: 'Cryptographic identity tokens issued.' })
  @ApiResponse({ status: 401, description: 'Zenith Shield: Authentication failed.' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`🔑 [AUTH_INGRESS] Authenticating identity: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  // ===========================================================================
  // SECTION: CRYPTOGRAPHIC SESSION OPERATIONS
  // ===========================================================================

  /**
   * CRYPTOGRAPHIC TOKEN ROTATION (REFRESH)
   * --------------------------------------
   * Performs the 'Burn-on-Use' protocol to rotate refresh credentials.
   * This is the primary detection point for token theft (RTR).
   * @throws ForbiddenException (403) If a reused or invalid token is presented.
   */
  @Public() // Bypasses global AT guard, strictly filtered by RtGuard
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Cryptographic Token Rotation (Refresh)' })
  @ApiResponse({ status: 200, description: 'Rotation cycle complete. New credentials issued.' })
  @ApiResponse({ status: 403, description: 'ZENITH_SHIELD: Breach detected / Token reuse attempt.' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    // ATOMIC EXTRACTION: Hydrated from the RtStrategy context
    const userId = req.user?.['id'];
    const rawRt = req.user?.['refreshToken'];

    this.logger.log(`🔄 [AUTH_ROTATION] Executing RTR cycle for ID: ${userId}`);

    /**
     * CORE DEFENSE:
     * Passing both the ID and the raw string to the service for DB-level validation.
     * This ensures 403 Forbidden is triggered if the hash doesn't match the current state.
     */
    return await this.authService.refreshTokens(userId, rawRt);
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
  @ApiResponse({ status: 200, description: 'Identity decoupled. Session registry cleared.' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = req.user?.['id'];
    this.logger.log(`🚪 [AUTH_REVOKE] Invalidating persistent session for ID: ${userId}`);
    return await this.authService.signout(userId);
  }

  /**
   * STATELESS SESSION AUDIT (STATUS)
   * --------------------------------
   * Exposes active PBAC claims without database I/O.
   */
  @UseGuards(PermissionsGuard)
  @Permissions('AUTH_STATUS_VIEW')
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Stateless Session Audit (Status)' })
  @ApiResponse({ status: 200, description: 'Session telemetry exposed.' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = req.user?.['id'];
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