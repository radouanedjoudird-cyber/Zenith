/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - DTO BARREL
 * ============================================================================
 * @file index.ts
 * @module AuthDTOs
 * @description Global Export Barrel for Zenith IAM Data Transfer Objects. 
 * This architectural pattern facilitates clean, centralized imports across 
 * the application kernel, reducing import noise in Controllers and Services.
 * @version 7.4.0
 * @author Radouane Djoudi
 * ============================================================================
 */

/** * @description Identity Provisioning DTO 
 */
export * from './signup.dto';

/** * @description Credential Verification DTO 
 */
export * from './signin.dto';

/** * @description Recovery Initiation Protocol DTO 
 */
export * from './request-recovery.dto';

/** * @description Credential Rotation Protocol DTO 
 */
export * from './reset-password.dto';
