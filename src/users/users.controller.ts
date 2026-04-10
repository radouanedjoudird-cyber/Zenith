import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
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
 * ZENITH USERS CONTROLLER - ENTERPRISE IDENTITY MANAGEMENT v2.8
 * -------------------------------------------------------------
 * ARCHITECTURE: Orchestrates the secure lifecycle of user-centric identity operations.
 * * SECURITY GOVERNANCE:
 * 1. PBAC (Permission-Based Access Control): Enforces "Principle of Least Privilege" at the routing layer.
 * 2. IDENTITY SYMMETRY: Seamlessly integrated with AtGuard for stateless identity resolution.
 * 3. FORENSIC TELEMETRY: Leverages AuditInterceptor to persist every state-changing transaction.
 * 4. PERFORMANCE: Stateless execution logic tailored for high-speed RTT on local infrastructure.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
@ApiTags('Identity & Access Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, PermissionsGuard) // Multi-layered Shield: Auth + Granular Permissions
@UseInterceptors(AuditInterceptor)     // Automated Telemetry for every sensitive request
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===========================================================================
  // MODULE: SELF-SERVICE (Standard Identity Operations)
  // ===========================================================================

  /**
   * SELF-PROFILE RETRIEVAL
   * Logic: Returns the authenticated user's own data registry.
   * Permission: 'PROFILE_READ'
   */
  @Permissions('PROFILE_READ')
  @Get('me')
  @ApiOperation({ 
    summary: 'Retrieve personal profile',
    description: 'Provides secure read-access to the authenticated subject\'s own metadata.' 
  })
  @ApiResponse({ status: 200, description: 'Identity context retrieved successfully.' })
  getMe(@GetCurrentUserId() userId: number) {
    /**
     * DATA INTEGRITY: The userId is extracted directly from the decrypted JWT payload 
     * using @GetCurrentUserId() to prevent ID-spoofing attacks.
     */
    return this.usersService.getMe(userId);
  }

  /**
   * SELF-PROFILE MODIFICATION
   * Logic: Performs partial updates on non-sensitive profile attributes.
   * Permission: 'PROFILE_UPDATE'
   */
  @Permissions('PROFILE_UPDATE')
  @Patch('me')
  @ApiOperation({ 
    summary: 'Update profile attributes',
    description: 'Enables partial modification of identity metadata with mass-assignment protection.' 
  })
  @ApiResponse({ status: 200, description: 'Profile attributes updated and audited.' })
  updateMe(@GetCurrentUserId() userId: number, @Body() dto: UpdateUserDto) {
    return this.usersService.updateMe(userId, dto);
  }

  /**
   * SELF-INITIATED ACCOUNT TERMINATION
   * Logic: Removes the user from the primary identity registry.
   * Permission: 'PROFILE_DELETE'
   */
  @Permissions('PROFILE_DELETE')
  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Self-initiated account termination',
    description: 'Permanently purges the user identity. This operation is recorded in high-severity logs.' 
  })
  @ApiResponse({ status: 200, description: 'Identity purged from system registry.' })
  deleteMe(@GetCurrentUserId() userId: number) {
    return this.usersService.deleteMe(userId);
  }

  // ===========================================================================
  // MODULE: ADMINISTRATIVE GOVERNANCE (Elevated Privileges)
  // ===========================================================================

  /**
   * GLOBAL REGISTRY DISCOVERY
   * Logic: Exposes the full user directory for administrative oversight.
   * Permission: 'USER_VIEW_ALL'
   */
  @Permissions('USER_VIEW_ALL')
  @Get()
  @ApiOperation({ 
    summary: 'Fetch all identities [ADMIN ONLY]',
    description: 'Administrative lookup for full system directory oversight.' 
  })
  @ApiResponse({ status: 200, description: 'Global user registry retrieved.' })
  getAllUsers() {
    return this.usersService.getAllUsers();
  }

  /**
   * TARGETED IDENTITY LOOKUP
   * Logic: Performs a surgical lookup of a specific identity via Unique Identifier.
   * Permission: 'USER_VIEW_SINGLE'
   */
  @Permissions('USER_VIEW_SINGLE')
  @Get(':id')
  @ApiOperation({ 
    summary: 'Targeted identity lookup [ELEVATED ONLY]',
    description: 'Executes a surgical ID lookup. Input is sanitized via ParseIntPipe.' 
  })
  @ApiResponse({ status: 200, description: 'Target identity context returned.' })
  getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }
}