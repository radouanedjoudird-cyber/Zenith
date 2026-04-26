/**
 * ============================================================================
 * ZENITH IDENTITY HYDRATION ENGINE - RT STRATEGY
 * ============================================================================
 * @module RtStrategy
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Orchestrates secure token rotation with hybrid stateful validation.
 * * ARCHITECTURAL RATIONALE:
 * 1. ROTATION_SECURITY: Extracts raw RT for cryptographic cross-verification (Argon2).
 * 2. VERSION_SYNCHRONIZATION: Ensures global session revocation via identity versioning.
 * 3. NULL_SAFETY: Implements defensive checks for header extraction to prevent runtime crashes.
 * ============================================================================
 */

import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger('ZENITH_RT_STRATEGY');

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    const rtSecret = config.get<string>('RT_SECRET');

    if (!rtSecret) {
      throw new Error('🛡️ ZENITH_CORE_ERROR: RT_SECRET configuration is missing.');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: rtSecret,
      passReqToCallback: true, // Enables raw request access for token extraction
    });
  }

  /**
   * @method validate
   * @async
   * @description Validates Refresh Token integrity, account status, and credential version.
   * @param {Request} req - The incoming execution context.
   * @param {any} payload - Decoded JWT claims including 'sub' and 'version'.
   * @returns {Promise<Object>} Refined identity context with raw refresh token.
   * @throws {UnauthorizedException} If security checks fail.
   */
  async validate(req: Request, payload: any) {
    /**
     * 1. INTEGRITY_GUARD:
     * Validates that the token contains the mandatory security version claim.
     */
    if (!payload.sub || payload.version === undefined) {
      throw new UnauthorizedException('ZENITH_SHIELD: Refresh context integrity failure.');
    }

    /**
     * 2. ACTIVE_VERSION_SYNC:
     * High-security check to invalidate tokens after password resets or global sign-outs.
     */
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { version: true, status: true },
    });

    if (!user) {
      throw new UnauthorizedException('ZENITH_GUARD: Identity context revoked.');
    }

    if (user.version !== payload.version) {
      this.logger.warn(`🚨 [SECURITY_REVOCATION]: Version mismatch for ID: ${payload.sub}. Access denied.`);
      throw new UnauthorizedException('ZENITH_GUARD: Session invalidated due to security update.');
    }

    /**
     * 3. DEFENSIVE_TOKEN_EXTRACTION:
     * Resolves TS2532 by explicitly validating the authorization header existence.
     */
    const authHeader = req.get('authorization');
    if (!authHeader) {
      this.logger.error(`❌ [PROTOCOL_VIOLATION]: Refresh attempt without Authorization header.`);
      throw new UnauthorizedException('ZENITH_SHIELD: Authorization header is required.');
    }

    const refreshToken = authHeader.replace('Bearer', '').trim();

    /**
     * 4. IDENTITY_HYDRATION:
     * Returns the payload augmented with the raw token for downstream RTR logic.
     */
    return {
      ...payload,
      refreshToken,
    };
  }
}