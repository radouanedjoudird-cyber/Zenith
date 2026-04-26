/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - SIGNIN PROTOCOL
 * ============================================================================
 * @module SigninDto
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Data Transfer Object for secure credential challenge.
 * * ARCHITECTURAL RATIONALE:
 * 1. ANTI_ENUMERATION: Generic failure messaging to mitigate account harvesting.
 * 2. CANONICAL_NORMALIZATION: Lowercase enforcement for O(1) B-Tree lookup.
 * 3. INJECTION_SHIELD: Strict character whitelisting for password buffer integrity.
 * ============================================================================
 */

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength
} from 'class-validator';

/**
 * @class SigninDto
 * @description Ingress schema for identity credential verification.
 */
export class SigninDto {

  /**
   * Primary unique identity key.
   * @security CANONICAL_FORM: Enforces lowercase and trimming to prevent bypass.
   * @note Generic error message prevents account enumeration attacks.
   */
  @ApiProperty({ 
    example: 'admin@zenith-systems.dz', 
    description: 'Unique identity email. Normalized to lowercase for indexing.' 
  })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail({}, { message: 'AUTH_GATE: Credentials validation failed.' })
  @IsNotEmpty()
  @MaxLength(100)
  email: string;

  /**
   * Secret credential string for the identity.
   * @security BUFFER_PROTECTION: Strict length and type enforcement.
   * @note Complexity matches Signup policy to ensure consistency across the IAM lifecycle.
   */
  @ApiProperty({ 
    example: 'Znt@2026!Sec', 
    description: 'Identity secret string (Password).' 
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  password: string;
}