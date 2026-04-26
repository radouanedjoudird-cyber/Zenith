import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
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
 * ============================================================================
 * ZENITH IDENTITY CONTROL PLANE - V7.4.0
 * ============================================================================
 * @class UsersController
 * @module IdentityModule
 * @description High-availability gateway for identity operations.
 * Implements strict Subject-Verb-Object (SVO) security patterns and
 * cross-origin resource sharing (CORS) compliance.
 *
 * GOVERNANCE & COMPLIANCE:
 * 1. ACCESS CONTROL: PermissionsGuard validates JWT scopes against the IAM registry.
 * 2. TELEMETRY: AuditInterceptor tracks all state-mutating requests (PATCH/DELETE).
 * 3. SCHEMA INTEGRITY: Enforces DTO-based validation for all ingress payloads.
 * 4. VERSIONING: Strictly follows Semantic Versioning via URI pathing (/v1).
 *
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * ============================================================================
 */
@ApiTags('Identity & Access Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, PermissionsGuard)
@UseInterceptors(AuditInterceptor)
@Controller({ path: 'users', version: '1' })
export class UsersController {
  private readonly logger = new Logger('ZENITH_IDENTITY_CONTROLLER');

  constructor(private readonly usersService: UsersService) {}

  // ---------------------------------------------------------------------------
  // SUBJECT-SCOPED OPERATIONS (Self-Service)
  // ---------------------------------------------------------------------------

  /**
   * @route   GET /api/v1/users/me
   * @desc    Retrieves the identity context of the currently authenticated subject.
   * @access  Private (PROFILE_READ)
   */
  @Permissions('PROFILE_READ')
  @Get('me')
  @ApiOperation({ 
    summary: 'Retrieve personal profile',
    description: 'Fetch detailed attributes of the currently logged-in user.' 
  })
  @ApiResponse({ status: 200, description: 'Identity context retrieved successfully.' })
  @ApiResponse({ status: 401, description: 'Authentication failed (Invalid/Expired Token).' })
  @ApiResponse({ status: 500, description: 'Internal kernel fault or corrupted identity pointer.' })
  async getMe(@GetCurrentUserId() userId: string) {
    this.logger.debug(`INGRESS [IDENTITY_FETCH]: Resolving context for subject ${userId}`);
    return await this.usersService.getMe(userId);
  }

  /**
   * @route   PATCH /api/v1/users/me
   * @desc    Performs partial synchronization of user attributes.
   * @access  Private (PROFILE_UPDATE)
   */
  @Permissions('PROFILE_UPDATE')
  @Patch('me')
  @ApiOperation({ 
    summary: 'Update profile attributes',
    description: 'Updates non-sensitive profile information and triggers audit logging.'
  })
  @ApiResponse({ status: 200, description: 'Profile updated and audited successfully.' })
  @ApiResponse({ status: 400, description: 'Validation failed (Check payload constraints).' })
  async updateMe(
    @GetCurrentUserId() userId: string, 
    @Body() dto: UpdateUserDto
  ) {
    this.logger.log(`INGRESS [IDENTITY_SYNC]: Mutating profile for subject ${userId}`);
    return await this.usersService.updateMe(userId, dto);
  }

  /**
   * @route   DELETE /api/v1/users/me
   * @desc    Initiates a permanent account termination sequence.
   * @access  Private (PROFILE_DELETE)
   */
  @Permissions('PROFILE_DELETE')
  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Self-initiated account termination',
    description: 'CAUTION: Permanently purges identity from the global registry.'
  })
  @ApiResponse({ status: 200, description: 'Identity purged and session terminated.' })
  async deleteMe(@GetCurrentUserId() userId: string) {
    this.logger.warn(`INGRESS [IDENTITY_PURGE]: Subject ${userId} initiated termination.`);
    return await this.usersService.deleteMe(userId);
  }

  // ---------------------------------------------------------------------------
  // ADMINISTRATIVE GOVERNANCE (Elevated Scope)
  // ---------------------------------------------------------------------------

  /**
   * @route   GET /api/v1/users
   * @desc    Returns a telemetry snapshot of all identities in the registry.
   * @access  Elevated (USER_VIEW_ALL)
   */
  @Permissions('USER_VIEW_ALL')
  @Get()
  @ApiOperation({ 
    summary: 'Fetch all identities [ADMIN ONLY]',
    description: 'Returns a full registry list for governance and auditing purposes.'
  })
  @ApiResponse({ status: 200, description: 'Global registry dump successful.' })
  @ApiResponse({ status: 403, description: 'Insufficient permissions (Requires USER_VIEW_ALL).' })
  async getAllUsers() {
    this.logger.debug('INGRESS [REGISTRY_SCAN]: Global discovery triggered.');
    return await this.usersService.getAllUsers();
  }

  /**
   * @route   GET /api/v1/users/:id
   * @desc    Targeted lookup of a specific identity via UUID.
   * @access  Elevated (USER_VIEW_SINGLE)
   */
  @Permissions('USER_VIEW_SINGLE')
  @Get(':id')
  @ApiOperation({ 
    summary: 'Targeted identity lookup [ELEVATED ONLY]',
    description: 'Lookup specific identity metadata using its unique identifier.'
  })
  @ApiResponse({ status: 200, description: 'Identity lookup successful.' })
  @ApiResponse({ status: 404, description: 'Target identity not found in registry.' })
  async getUserById(@Param('id') id: string) {
    this.logger.debug(`INGRESS [IDENTITY_LOOKUP]: Fetching profile for target ${id}`);
    return await this.usersService.getUserById(id);
  }
}