/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - IDENTITY PROVISIONING PROTOCOL
 * ============================================================================
 * @module SignupDto
 * @version 7.4.0
 * @author Radouane Djoudi
 * @description Data Transfer Object for secure new identity registration.
 * * ARCHITECTURAL RATIONALE:
 * 1. XSS_DEFENSE: Aggressive Regex-based HTML stripping for all ingress strings.
 * 2. E.164_COMPLIANCE: Strict validation for international mobile identities.
 * 3. ENTROPY_ENFORCEMENT: MIL-SPEC complexity parity for initial credentialing.
 * ============================================================================
 */

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator';

/**
 * @class SignupDto
 * @description Ingress schema for new identity provisioning in the Zenith ecosystem.
 */
export class SignupDto {
  
  /**
   * Applicant's legal first name.
   * @security SANITIZATION: Strips script/HTML tags at the ingress point to prevent XSS.
   */
  @ApiProperty({ 
    example: 'Radouane',
    description: 'Legal first name of the applicant' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value
  )
  firstName: string;

  /**
   * Applicant's legal family name.
   * @normalization B-TREE_OPTIMIZED: Trimmed and sanitized for high-performance indexing.
   */
  @ApiProperty({ 
    example: 'Djoudi',
    description: 'Legal family name of the applicant' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value
  )
  familyName: string;

  /**
   * ITU-T E.164 compliant phone number for DZ region.
   * @normalization DZ_CLEANING: Removes internal whitespaces for consistent DB matching.
   */
  @ApiProperty({ 
    example: '+213661234567',
    description: 'International E.164 formatted phone number' 
  })
  @IsPhoneNumber('DZ') 
  @IsNotEmpty()
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/\s/g, '') : value
  )
  phoneNumber: string;

  /**
   * Primary unique identity key (Email).
   * @security CANONICAL_FORM: Enforces lowercase to ensure database-level uniqueness.
   */
  @ApiProperty({ 
    example: 'contact@zenith-systems.dz',
    description: 'Unique email address for identity binding' 
  })
  @IsEmail({}, { message: 'SECURITY_ALERT: Malformed email structure detected.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  email: string;

  /**
   * High-entropy password requirement for the new identity.
   * @complexity POLICY: 10-32 chars, must include [A-Z], [a-z], [0-9], and Special Chars.
   */
  @ApiProperty({ 
    example: 'Znt@2026!Sec',
    description: 'High-entropy password meeting Zenith complexity standards' 
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'SECURITY_POLICY: Password entropy requirements not met.',
  })
  password: string;
}