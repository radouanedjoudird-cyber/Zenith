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
import { GetCurrentUserId, Roles } from '../common/decorators';
import { Role } from '../common/enums/role.enum';
import { RolesGuard } from '../common/guards/roles.guard';
import { UpdateUserDto } from './dto';
import { UsersService } from './users.service';

/**
 * ZENITH USERS CONTROLLER - ENTERPRISE EDITION
 * -------------------------------------------
 * Orchestrates user-related operations with high-security standards.
 * IMPLEMENTS: RBAC (Role-Based Access Control) & JWT Authentication.
 */
@ApiTags('Users Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, RolesGuard) // Dual-layer protection: Auth + Authorization
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===========================================================================
  // SELF-SERVICE MODULE (Standard User Privileges)
  // ===========================================================================

  @Get('me')
  @ApiOperation({ summary: 'Retrieve personal profile of the authenticated user' })
  @ApiResponse({ status: 200, description: 'User data returned securely.' })
  getMe(@GetCurrentUserId() userId: number) {
    return this.usersService.getMe(userId);
  }

  @Put('me')
  @ApiOperation({ summary: 'Update personal profile information' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully.' })
  @ApiResponse({ status: 409, description: 'Conflict: Identity attributes already in use.' })
  updateMe(@GetCurrentUserId() userId: number, @Body() dto: UpdateUserDto) {
    return this.usersService.updateMe(userId, dto);
  }

  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Self-initiated account termination' })
  @ApiResponse({ status: 200, description: 'Account purged from production.' })
  deleteMe(@GetCurrentUserId() userId: number) {
    return this.usersService.deleteMe(userId);
  }

  // ===========================================================================
  // ADMINISTRATIVE MODULE (Elevated Privileges Only)
  // ===========================================================================

  /**
   * SECURITY: ADMIN_ONLY
   * Provides global visibility for system oversight.
   */
  @Roles(Role.ADMIN)
  @Get()
  @ApiOperation({ summary: 'Fetch all registered users [ADMIN ONLY]' })
  @ApiResponse({ status: 200, description: 'Full user directory retrieved.' })
  @ApiResponse({ status: 403, description: 'Forbidden: Admin role required.' })
  getAllUsers() {
    return this.usersService.getAllUsers();
  }

  /**
   * SECURITY: ADMIN_MODERATOR
   * Targeted lookup for administrative or support purposes.
   */
  @Roles(Role.ADMIN, Role.MODERATOR)
  @Get(':id')
  @ApiOperation({ summary: 'Retrieve specific user by ID [ELEVATED ONLY]' })
  @ApiResponse({ status: 200, description: 'Target user found.' })
  @ApiResponse({ status: 404, description: 'Target user not located.' })
  getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }
}