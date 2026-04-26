/**
 * ============================================================================
 * ZENITH SECURITY KERNEL - DYNAMIC PBAC GUARD
 * ============================================================================
 * @module PermissionsGuard
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Mission-critical gatekeeper for Permission-Based Access Control.
 * * ARCHITECTURAL RATIONALE:
 * 1. WILDCARD_AUTHORITY: Grants immediate access if '*' claim is present.
 * 2. GRANULAR_VALIDATION: Fallback to strict PBAC if no wildcard exists.
 * 3. HARDWARE_AWARE_AUDIT: Captures OS/Browser telemetry for forensic trails.
 * ============================================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { LogStatus, Severity } from '@prisma/client';
import { UAParser } from 'ua-parser-js';
import { PrismaService } from '../../prisma/prisma.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger('ZENITH_SECURITY_GUARD');

  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // [1] BYPASS_LOGIC: No permissions required
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const { user, ip, method, url } = request;
    const userAgent = request.get('user-agent') || 'Unknown Origin';
    
    // Parse Hardware Telemetry for Auditing
    const ua = new UAParser(userAgent).getResult();
    const os = ua.os.name || 'Unknown OS';
    const browser = ua.browser.name || 'Unknown Browser';

    // [2] IDENTITY_INTEGRITY_CHECK
    if (!user || !user.perms) {
      this.logger.error(`🚨 [SECURITY_BREACH] Identity context corrupted for ${url} | IP: ${ip}`);
      throw new ForbiddenException('ZENITH_SHIELD: Identity context integrity failure.');
    }

    /**
     * [3] PROFESSIONAL_AUTHORIZATION_LOGIC
     * Logic: (Has Wildcard '*') OR (Has all required permissions)
     */
    const hasWildcard = user.perms.includes('*');
    const hasStrictPermissions = requiredPermissions.every((perm) =>
      user.perms.includes(perm),
    );

    const isAuthorized = hasWildcard || hasStrictPermissions;

    if (!isAuthorized) {
      // [4] FORENSIC_ESCALATION
      await this.persistSecurityViolation({
        user, method, url, ip, userAgent, os, browser, requiredPermissions
      });
      
      throw new ForbiddenException({
        success: false,
        statusCode: 403,
        message: 'Account protection protocols engaged. Insufficient granular privileges.',
        error: 'SECURITY_INTEGRITY_VIOLATION',
        protection_id: `PROT-${Math.random().toString(36).toUpperCase().substring(2, 9)}`
      });
    }

    return true;
  }

  /**
   * @private persistSecurityViolation
   * @description Records unauthorized access attempts with full hardware telemetry.
   */
  private async persistSecurityViolation(ctx: any) {
    const { user, method, url, ip, userAgent, os, browser, requiredPermissions } = ctx;
    
    this.logger.warn(`⚠️ [ACCESS_DENIED] Identity ${user.email} flagged for unauthorized attempt on ${url}`);

    try {
      await this.prisma.auditLog.create({
        data: {
          action: 'SECURITY_BREACH_ATTEMPT',
          entity: 'SecurityGuard',
          path: url,
          method: method,
          userId: user.sub || user.id,
          userEmail: user.email,
          ipAddress: ip === '::1' ? '127.0.0.1' : ip,
          userAgent: userAgent,
          os: os,           // 🛡️ Fixed: Matches our new Schema
          browser: browser, // 🛡️ Fixed: Matches our new Schema
          status: LogStatus.DENIED, 
          severity: Severity.HIGH,
          payload: {
            required_claims: requiredPermissions,
            presented_claims: user.perms,
            violation_type: 'PBAC_INSUFFICIENT_PRIVILEGES'
          }
        }
      });
    } catch (err) {
      this.logger.error(`❌ [FORENSIC_FAILURE] Unable to persist security trail: ${err.message}`);
    }
  }
}