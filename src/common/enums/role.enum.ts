/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT (IAM) - CORE ROLE REGISTRY
 * ============================================================================
 * @module Role
 * @version 7.4.0
 * @author Zenith Systems Engine
 * @description Centralized Authority for system-wide role definitions.
 * * * ARCHITECTURAL COMPLIANCE:
 * 1. IMMUTABILITY: Enforced via TypeScript 'as const' and Enum patterns.
 * 2. SINGLE_SOURCE_OF_TRUTH: Synchronized with the 'Role' collection in the Data Registry.
 * 3. HIERARCHICAL_MAPPING: Designed for privilege escalation and bypass logic.
 * ============================================================================
 */

/**
 * @enum Role
 * @description Defines the cryptographic string representations of system identities.
 * These values are bound to JWT 'role' claims and database persistence layers.
 */
export enum Role {
  /**
   * @identity CONSUMER
   * Standard consumer identity with baseline self-service privileges.
   */
  USER = 'USER',

  /**
   * @identity SYSTEM_ADMIN
   * Administrative control over business logic, user management, and IAM kernel.
   */
  ADMIN = 'ADMIN',

  /**
   * @identity CONTENT_MODERATOR
   * Specialized identity for content governance, safety enforcement, and moderation.
   */
  MODERATOR = 'MODERATOR',

  /**
   * @identity SECURITY_AUDITOR
   * Read-only elevated access for forensic review, compliance auditing, and logging.
   */
  AUDITOR = 'AUDITOR',

  /**
   * @identity INFRASTRUCTURE_SUPER_ADMIN
   * Highest-level identity with absolute authority over kernel and infrastructure.
   * [WARNING] This role triggers 'Privilege Bypass' in security guards.
   */
  SUPER_ADMIN = 'SUPER_ADMIN',
}

/**
 * @type RoleType
 * @description Derived type for high-level identity manipulation.
 */
export type RoleType = keyof typeof Role;