/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - SIGNIN PROTOCOL
 * ============================================================================
 * @module SigninDto
 * @version 7.4.0
 * @description Data Transfer Object for secure credential challenge.
 * * ARCHITECTURAL RATIONALE:
 * 1. ANTI_HARVESTING: Generic messaging to prevent identity enumeration.
 * 2. CANONICAL_FORMATTING: Lowercase normalization for O(1) B-Tree lookup.
 * 3. INJECTION_SHIELD: Strict character whitelisting for password buffer.
 * ============================================================================
 */

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class SigninDto {

  @ApiProperty({ 
    example: 'admin@zenith-systems.dz', 
    description: 'Unique identity email. Normalized to lowercase for indexing.' 
  })
  /**
   * CREDENTIAL NORMALIZATION:
   * Ensures that whitespace and case-sensitivity issues do not result 
   * in false-negative authentication failures.
   */
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail({}, { message: 'AUTH_GATE: Credentials validation failed.' })
  @IsNotEmpty()
  @MaxLength(100)
  email: string;

  @ApiProperty({ 
    example: 'Znt@2026!Sec', 
    description: 'Identity secret string (Password).' 
  })
  /**
   * INPUT SECURITY:
   * Enforces the same character constraints as the Provisioning (Signup) phase
   * to mitigate injection risks while maintaining cryptographic entropy.
   */
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  /**
   * SECURITY POLICY:
   * Using generic error messages to block account discovery via timing or response delta.
   */
  @Matches(/^[A-Za-z\d@$!%*?&_#^()]*$/, {
    message: 'AUTH_GATE: Credentials validation failed.',
  })
  password: string;
}