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
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * SECURITY GOVERNANCE:
 * 1. PBAC (Permission-Based Access Control): Enforces "Principle of Least Privilege".
 * 2. IDENTITY_SYMMETRY: Integrated with AtGuard for stateless resolution.
 * 3. FORENSIC_TELEMETRY: Automated capture of state-changing transactions.
 * 4. API_STABILITY: Implements URI-based versioning (v1).
 */
@ApiTags('Identity & Access Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(AtGuard, PermissionsGuard) // Layered Defense: Auth + Permission Checks
@UseInterceptors(AuditInterceptor)     // Telemetry: Every change is audited
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===========================================================================
  // MODULE: SELF-SERVICE (Subject-Scoped Operations)
  // ===========================================================================

  /**
   * SELF-PROFILE RETRIEVAL
   * ----------------------
   * Access: Subject's own secure data.
   */
  @Permissions('PROFILE_READ')
  @Get('me')
  @ApiOperation({ summary: 'Retrieve personal profile' })
  @ApiResponse({ status: 200, description: 'Identity context retrieved successfully.' })
  getMe(@GetCurrentUserId() userId: number) {
    /**
     * SECURITY: userId is extracted from JWT (req.user.id), 
     * making it immune to parameter tampering.
     */
    return this.usersService.getMe(userId);
  }

  /**
   * SELF-PROFILE MODIFICATION
   * -------------------------
   * Logic: Partial update with mass-assignment protection via DTO.
   */
  @Permissions('PROFILE_UPDATE')
  @Patch('me')
  @ApiOperation({ summary: 'Update profile attributes' })
  @ApiResponse({ status: 200, description: 'Profile updated and audited.' })
  updateMe(@GetCurrentUserId() userId: number, @Body() dto: UpdateUserDto) {
    return this.usersService.updateMe(userId, dto);
  }

  /**
   * SELF-INITIATED ACCOUNT TERMINATION
   * ----------------------------------
   * Logic: Critical event. Logged as HIGH-SEVERITY in Audit Logs.
   */
  @Permissions('PROFILE_DELETE')
  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Self-initiated account termination' })
  @ApiResponse({ status: 200, description: 'Identity purged from registry.' })
  deleteMe(@GetCurrentUserId() userId: number) {
    return this.usersService.deleteMe(userId);
  }

  // ===========================================================================
  // MODULE: ADMINISTRATIVE GOVERNANCE (Elevated Privileges)
  // ===========================================================================

  /**
   * GLOBAL REGISTRY DISCOVERY
   * -------------------------
   * Access: Administrative lookup only.
   */
  @Permissions('USER_VIEW_ALL')
  @Get()
  @ApiOperation({ summary: 'Fetch all identities [ADMIN ONLY]' })
  getAllUsers() {
    return this.usersService.getAllUsers();
  }

  /**
   * TARGETED IDENTITY LOOKUP
   * ------------------------
   * Logic: Surgical ID lookup with Type-Safety (ParseIntPipe).
   */
  @Permissions('USER_VIEW_SINGLE')
  @Get(':id')
  @ApiOperation({ summary: 'Targeted identity lookup [ELEVATED ONLY]' })
  getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }
}