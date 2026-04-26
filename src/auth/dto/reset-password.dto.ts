/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - CREDENTIAL ROTATION PROTOCOL
 * ============================================================================
 * @module ResetPasswordDto
 * @version 7.4.0
 * @description Data Transfer Object for finalizing credential rotation via cryptographic token.
 * * ARCHITECTURAL RATIONALE:
 * 1. ENTROPY_PARITY: Synchronizes complexity requirements with the Signup Protocol.
 * 2. INTEGRITY_VALIDATION: Mandatory token-based authentication for stateless recovery.
 * 3. PARITY_ENFORCEMENT: Client-side confirmation string for UI/UX synchronization.
 * ============================================================================
 */

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
    IsNotEmpty,
    IsString,
    Matches,
    MaxLength,
    MinLength
} from 'class-validator';

/**
 * @class ResetPasswordDto
 * @description Final protocol payload for rotating identity credentials.
 */
export class ResetPasswordDto {
  
  /**
   * Cryptographic recovery token issued via the RTR signaling stage.
   * @type {string}
   * @security INTEGRITY: Validated against the SHA-256 hash in the persistence layer.
   */
  @ApiProperty({ 
    description: 'The unique hex-encoded recovery token issued to the identity.',
    example: 'a7b8c9d0e1f2b3c4d5e6f7a8b9c0d1e2' 
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
  token: string;

  /**
   * New high-entropy password for the identity.
   * @type {string}
   * @security COMPLEXITY: Requires [A-Z], [a-z], [0-9], and Special Characters.
   * @complexity MIN_LENGTH: 10, MAX_LENGTH: 32.
   */
  @ApiProperty({ 
    example: 'Znt@2026!NewPass', 
    description: 'New password compliant with Zenith entropy requirements.' 
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'SECURITY_POLICY: New password complexity requirements not met.',
  })
  newPassword: string;

  /**
   * Parity confirmation string for the new password.
   * @type {string}
   * @note Business logic validation (parity check) is executed within the AuthService.
   */
  @ApiProperty({ 
    example: 'Znt@2026!NewPass', 
    description: 'Confirmation string to ensure credential accuracy.' 
  })
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
  confirmPassword: string;

}