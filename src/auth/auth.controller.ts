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
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { AtGuard } from './guards/at.guard';
import { RtGuard } from './guards/rt.guard';

/**
 * ZENITH AUTHENTICATION CONTROLLER:
 * Handles all authentication-related HTTP requests.
 * Each route is protected by the appropriate guard:
 * - Public routes: signup, signin (no guard)
 * - Access token routes: status (AtGuard)
 * - Refresh token routes: refresh, signout (RtGuard)
 */
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  // ─────────────────────────────────────────────
  // PUBLIC ROUTES
  // ─────────────────────────────────────────────

  /**
   * SIGNUP:
   * Registers a new user and returns a full token pair.
   * No authentication required — this is the entry point.
   */
  @Post('signup')
  @ApiOperation({ summary: 'Register a new user and receive token pair' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log(`New registration request for: ${signupDto.email}`);
    return await this.authService.signup(signupDto);
  }

  /**
   * SIGNIN:
   * Authenticates an existing user and returns a full token pair.
   * No authentication required — credentials are validated internally.
   */
  @Post('signin')
  @ApiOperation({ summary: 'Authenticate and receive token pair' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`Authentication request for: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  // ─────────────────────────────────────────────
  // ACCESS TOKEN ROUTES
  // ─────────────────────────────────────────────

  /**
   * STATUS:
   * Verifies the access token and returns the user profile.
   * Protected by AtGuard — requires a valid, non-expired access token.
   */
  @UseGuards(AtGuard)
  @Get('status')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Verify access token and retrieve profile' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    const userId = req.user?.['sub'];
    this.logger.log(`Status check for User ID: ${userId}`);

    return {
      status: 'authenticated',
      timestamp: new Date().toISOString(),
      profile: req.user,
    };
  }

  // ─────────────────────────────────────────────
  // REFRESH TOKEN ROUTES
  // ─────────────────────────────────────────────

  /**
   * REFRESH:
   * Issues a brand new token pair using a valid refresh token.
   * Protected by RtGuard — requires a valid, non-expired refresh token.
   * The old refresh token is immediately invalidated (Token Rotation).
   */
  @UseGuards(RtGuard)
  @Post('refresh')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Rotate token pair using refresh token' })
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const userId = req.user?.['sub'];
    const rawRt = req.user?.['refreshToken'];
    this.logger.log(`Token rotation request for User ID: ${userId}`);

    return await this.authService.refreshTokens(userId, rawRt);
  }

  /**
   * SIGNOUT:
   * Revokes the refresh token by setting hashedRt to null in the database.
   * Protected by RtGuard — requires a valid refresh token to sign out.
   * After this, both tokens are completely useless.
   */
  @UseGuards(RtGuard)
  @Post('signout')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Revoke refresh token and terminate session' })
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = req.user?.['sub'];
    this.logger.log(`Signout request for User ID: ${userId}`);

    return await this.authService.signout(userId);
  }
}