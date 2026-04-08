import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Patch, // ADDED: More appropriate for partial updates in Enterprise APIs
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Role } from '@prisma/client'; // High-Level Type Safety
import { AtGuard } from '../auth/guards/at.guard';
import { GetCurrentUserId } from '../common/decorators/get-current-user-id.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { RolesGuard } from '../common/guards/roles.guard'; // FIXED: Pointing to the new centralized location
import { AuditInterceptor } from '../common/interceptors/audit.interceptor';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';

/**
 * ZENITH USERS CONTROLLER - ENTERPRISE EDITION
 * -------------------------------------------
 * Orchestrates user-related operations with high-security standards.
 * IMPLEMENTS: RBAC (Role-Based Access Control), JWT Auth & Forensic Auditing.
 * INFRASTRUCTURE: Optimized for HP-ProBook deployment environment.
 */
@ApiTags('Users Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, RolesGuard) // Dual-layer protection: Auth + Authorization
@UseInterceptors(AuditInterceptor) // Forensic Logging Layer
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===========================================================================
  // SELF-SERVICE MODULE (Standard User Privileges)
  // ===========================================================================

  @Get('me')
  @ApiOperation({ summary: 'Retrieve personal profile of the authenticated user' })
  @ApiResponse({ status: 200, description: 'User data returned securely.' })
  /**
   * DATA PRIVACY: Ensures users can only access their own data via JWT payload identification.
   */
  getMe(@GetCurrentUserId() userId: number) {
    return this.usersService.getMe(userId);
  }

  @Patch('me') // CHANGED: Standardized to PATCH for DTO-based partial updates
  @ApiOperation({ summary: 'Update personal profile information' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully.' })
  @ApiResponse({ status: 409, description: 'Conflict: Identity attributes already in use.' })
  /**
   * INTEGRITY CHECK: Prevents mass-assignment via Whitelisted DTO.
   */
  updateMe(@GetCurrentUserId() userId: number, @Body() dto: UpdateUserDto) {
    return this.usersService.updateMe(userId, dto);
  }

  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Self-initiated account termination' })
  @ApiResponse({ status: 200, description: 'Account purged from production.' })
  /**
   * DESTRUCTIVE ACTION: Automatically triggers AuditLog via Interceptor.
   */
  deleteMe(@GetCurrentUserId() userId: number) {
    return this.usersService.deleteMe(userId);
  }

  // ===========================================================================
  // ADMINISTRATIVE MODULE (Elevated Privileges Only)
  // ===========================================================================

  /**
   * SECURITY: ADMIN_ONLY
   * Provides global visibility for system oversight.
   * ACCESS_LEVEL: High (Strictly Audit-Logged)
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
   * ACCESS_LEVEL: Elevated
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