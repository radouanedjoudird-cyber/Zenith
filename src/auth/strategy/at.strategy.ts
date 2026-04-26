/**
 * ============================================================================
 * ZENITH IDENTITY HYDRATION ENGINE - AT STRATEGY v7.4.0
 * ============================================================================
 * @module AtStrategy
 * @version 7.5.0
 * @author Radouane Djoudi
 * @description Orchestrates stateless identity resolution with active version validation.
 * * ARCHITECTURAL RATIONALE:
 * 1. VERSION_SYNCHRONIZATION: Ensures global session revocation upon credential rotation.
 * 2. CRYPTOGRAPHIC_INTEGRITY: Validates Access Tokens using dedicated secrets.
 * 3. HYBRID_STATEFUL_VALIDATION: Database check to ensure real-time security state.
 * ============================================================================
 */

import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * @class AtStrategy
 * @extends {PassportStrategy(Strategy, 'jwt')}
 * @description The core cryptographic validator for Zenith Secure Engine.
 */
@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger('ZENITH_AT_STRATEGY');

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    /**
     * 🟢 FIX [TS17009]: Initialize the parent class BEFORE executing internal logic.
     * We pull the secret directly within the super call to satisfy the compiler.
     */
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('AT_SECRET') || 'ZENITH_FALLBACK_SECRET',
    });

    // Post-initialization check
    if (!config.get<string>('AT_SECRET')) {
      this.logger.error('🛡️ ZENITH_CORE_ERROR: AT_SECRET is not defined in the environment registry.');
    }
  }

  /**
   * ZENITH IDENTITY VALIDATION GATE
   * ------------------------------
   * @method validate
   * @async
   * @description Final validation gate with Identity Versioning check.
   * @param {any} payload - { sub: string, email: string, role: string, perms: string[], version: number }
   * @returns {Promise<any>} Authorized identity object injected into req.user
   * @throws {UnauthorizedException} If identity context is lost or version mismatch occurs.
   */
  async validate(payload: any): Promise<any> {
    /**
     * PHASE 1: INTEGRITY_CHECK
     * Standard OIDC claims verification.
     */
    if (!payload || !payload.sub || payload.version === undefined) {
      throw new UnauthorizedException('ZENITH_SHIELD: Security context integrity failure.');
    }

    /**
     * PHASE 2: ACTIVE_VERSION_VERIFICATION (Hybrid Check)
     * Real-time DB lookup to support immediate session revocation (Global Logout).
     */
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { version: true, status: true },
    });

    /**
     * PHASE 3: ANOMALY_DETECTION & REVOCATION
     */
    if (!user) {
      throw new UnauthorizedException('ZENITH_GUARD: Identity context revoked or lost.');
    }

    /**
     * 🛡️ VERSION CHECK LOGIC:
     * Validates that the token version matches the persistent storage version.
     */
    if (user.version !== payload.version) {
      this.logger.warn(`🚨 [SECURITY_REVOCATION]: Version mismatch for ID: ${payload.sub}. Forced re-authentication.`);
      throw new UnauthorizedException('ZENITH_GUARD: Session expired due to credential rotation.');
    }

    if (user.status !== 'ACTIVE') {
      this.logger.warn(`🚨 [ACCESS_DENIED]: Inactive account access attempt for ID: ${payload.sub}`);
      throw new UnauthorizedException('ZENITH_GUARD: Identity is currently flagged or inactive.');
    }

    /**
     * PHASE 4: IDENTITY_HYDRATION
     * ---------------------------
     * Standardizes the user object for downstream PermissionGuards and Decorators.
     * Note: 'sub' is the primary identifier for Zenith Secure Engine.
     */
    return {
      sub: payload.sub,
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      perms: payload.perms,
      version: payload.version,
    };
  }
}