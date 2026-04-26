import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AtGuard } from '../auth/guards/at.guard';
import { GetCurrentUserId } from '../common/decorators/get-current-user-id.decorator';
import { Permissions } from '../common/decorators/permissions.decorator';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { AuditInterceptor } from '../common/interceptors/audit.interceptor';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';

/**
 * ZENITH USERS CONTROLLER - ENTERPRISE IDENTITY MANAGEMENT v4.1 (MongoDB Edition)
 * -------------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * SECURITY GOVERNANCE:
 * 1. PBAC (Permission-Based Access Control): Enforces "Principle of Least Privilege".
 * 2. MIGRATION: Refactored for String-based BSON ObjectIDs.
 * 3. FORENSIC_TELEMETRY: Automated capture of state-changing transactions.
 * 4. API_STABILITY: Implements URI-based versioning (v1).
 */
@ApiTags('Identity & Access Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, PermissionsGuard)
@UseInterceptors(AuditInterceptor)
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===========================================================================
  // MODULE: SELF-SERVICE (Subject-Scoped Operations)
  // ===========================================================================

  /**
   * SELF-PROFILE RETRIEVAL
   */
  @Permissions('PROFILE_READ')
  @Get('me')
  @ApiOperation({ summary: 'Retrieve personal profile' })
  @ApiResponse({ status: 200, description: 'Identity context retrieved successfully.' })
  getMe(@GetCurrentUserId() userId: string) { // Changed to string
    return this.usersService.getMe(userId);
  }

  /**
   * SELF-PROFILE MODIFICATION
   */
  @Permissions('PROFILE_UPDATE')
  @Patch('me')
  @ApiOperation({ summary: 'Update profile attributes' })
  @ApiResponse({ status: 200, description: 'Profile updated and audited.' })
  updateMe(@GetCurrentUserId() userId: string, @Body() dto: UpdateUserDto) { // Changed to string
    return this.usersService.updateMe(userId, dto);
  }

  /**
   * SELF-INITIATED ACCOUNT TERMINATION
   */
  @Permissions('PROFILE_DELETE')
  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Self-initiated account termination' })
  @ApiResponse({ status: 200, description: 'Identity purged from registry.' })
  deleteMe(@GetCurrentUserId() userId: string) { // Changed to string
    return this.usersService.deleteMe(userId);
  }

  // ===========================================================================
  // MODULE: ADMINISTRATIVE GOVERNANCE (Elevated Privileges)
  // ===========================================================================

  /**
   * GLOBAL REGISTRY DISCOVERY
   */
  @Permissions('USER_VIEW_ALL')
  @Get()
  @ApiOperation({ summary: 'Fetch all identities [ADMIN ONLY]' })
  getAllUsers() {
    return this.usersService.getAllUsers();
  }

  /**
   * TARGETED IDENTITY LOOKUP
   * REFINED: Removed ParseIntPipe to support MongoDB BSON ObjectIDs (String).
   */
  @Permissions('USER_VIEW_SINGLE')
  @Get(':id')
  @ApiOperation({ summary: 'Targeted identity lookup [ELEVATED ONLY]' })
  getUserById(@Param('id') id: string) { // Removed ParseIntPipe and changed to string
    return this.usersService.getUserById(id);
  }
}