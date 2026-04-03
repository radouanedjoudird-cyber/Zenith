import { Body, Controller, Get, HttpCode, HttpStatus, Logger, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { SigninDto, SignupDto } from './dto';
import { AtGuard } from './guards/at.guard';

@ApiTags('Authentication') // Swagger grouping
@ApiBearerAuth('JWT-auth') // LINK TO main.ts SECURITY DEFINITION
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({ summary: 'Register a new high-security user' })
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    this.logger.log(`Registering user: ${signupDto.email}`);
    return await this.authService.signup(signupDto);
  }

  @Post('signin')
  @ApiOperation({ summary: 'Generate JWT access token' })
  @HttpCode(HttpStatus.OK)
  async signin(@Body() signinDto: SigninDto) {
    this.logger.log(`Authentication request for: ${signinDto.email}`);
    return await this.authService.signin(signinDto);
  }

  @UseGuards(AtGuard)
  @Get('status')
  @ApiBearerAuth('JWT-auth') // Explicitly show lock icon in Swagger for this route
  @ApiOperation({ summary: 'Verify session and retrieve profile' })
  @HttpCode(HttpStatus.OK)
  async getStatus(@Req() req: Request) {
    // req.user is populated by JwtStrategy.validate()
    const userId = req.user?.['id'];
    this.logger.log(`High-speed status check for User ID: ${userId}`);
    
    return {
      status: 'authenticated',
      timestamp: new Date().toISOString(),
      profile: req.user, 
    };
  }
}