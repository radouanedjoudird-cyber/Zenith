import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Put,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AtGuard } from '../auth/guards/at.guard';
import { GetCurrentUserId } from '../common/decorators';
import { UpdateUserDto } from './dto';
import { UsersService } from './users.service';

/**
 * ZENITH USERS CONTROLLER - SECURE GATEWAY
 * ----------------------------------------
 * Manages HTTP orchestration for profile lifecycle and administration.
 * SECURITY: Standardized on JWT Access Tokens via AtGuard.
 */
@ApiTags('Users Management')
@ApiBearerAuth('JWT-auth') // Applied globally to the controller for cleaner Swagger UI
@UseGuards(AtGuard)        // Applied globally: All user routes require a token
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ──────────────────────────────────────────────────────────────────────────
  // SELF-SERVICE ENDPOINTS (Authenticated Users)
  // ──────────────────────────────────────────────────────────────────────────

  @Get('me')
  @ApiOperation({ summary: 'Retrieve current authenticated user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved successfully.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  getMe(@GetCurrentUserId() userId: number) {
    return this.usersService.getMe(userId);
  }

  @Put('me')
  @ApiOperation({ summary: 'Update current authenticated user profile' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully.' })
  @ApiResponse({ status: 409, description: 'Conflict: Email or Phone already exists.' })
  updateMe(
    @GetCurrentUserId() userId: number, 
    @Body() dto: UpdateUserDto
  ) {
    return this.usersService.updateMe(userId, dto);
  }

  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Permanently delete current user account' })
  @ApiResponse({ status: 200, description: 'Account deleted.' })
  deleteMe(@GetCurrentUserId() userId: number) {
    return this.usersService.deleteMe(userId);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // ADMINISTRATIVE ENDPOINTS (RBAC Placeholder)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * ADMIN ONLY: Get all users.
   * NOTE: In the next step, we will add @Roles(Role.ADMIN) here.
   */
  @Get()
  @ApiOperation({ summary: 'List all users [ADMIN ONLY]' })
  @ApiResponse({ status: 403, description: 'Forbidden: Insufficient privileges.' })
  getAllUsers() {
    // Audit Note: This call currently requires only a valid token. 
    // RBAC Guard will be attached here to lock it to Admins.
    return this.usersService.getAllUsers();
  }

  /**
   * ADMIN/MODERATOR ONLY: Get specific user.
   */
  @Get(':id')
  @ApiOperation({ summary: 'Find specific user by ID [ADMIN ONLY]' })
  getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }
}