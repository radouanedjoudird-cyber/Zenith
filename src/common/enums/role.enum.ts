/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) - STATIC ROLE CONSTANTS
 * ============================================================================
 * @module RoleConstants
 * @version 7.4.0
 * @description Defines the core system roles for bootstrap and internal logic.
 * * * ARCHITECTURAL NOTE:
 * Since v7.4.0, Zenith uses Dynamic RBAC (stored in MongoDB). This file 
 * serves as a static reference for hardcoded system logic and seeding.
 * ============================================================================
 */

/**
 * @constant Role
 * @description Immutable reference for primary system identities.
 * These must exist in the 'role' collection in MongoDB for system integrity.
 */
export const Role = {
  /** Standard consumer identity with baseline privileges */
  USER: 'USER',

  /** Full administrative control over the IAM kernel */
  ADMIN: 'ADMIN',

  /** Identity focused on content governance and moderation */
  MODERATOR: 'MODERATOR',

  /** Specialized identity for security auditing and forensic review */
  AUDITOR: 'AUDITOR',

  /** Elevated administrative identity for infrastructure-level operations */
  SUPER_ADMIN: 'SUPER_ADMIN',
} as const;

/**
 * @type Role
 * @description Type-safe extraction of Role values for TypeScript compiler safety.
 */
export type Role = (typeof Role)[keyof typeof Role];