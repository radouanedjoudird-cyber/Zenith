/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - SIGNUP PROTOCOL
 * ============================================================================
 * @module SignupDto
 * @version 7.4.0
 * @description Data Transfer Object for secure identity provisioning.
 * * ARCHITECTURAL RATIONALE:
 * 1. XSS_DEFENSE: Aggressive Regex-based HTML stripping for inbound strings.
 * 2. NORMALIZATION: Canonical indexing via lowercase & trim transformations.
 * 3. COMPLEXITY_ENFORCEMENT: MIL-SPEC entropy requirements for passwords.
 * 4. PRIVILEGE_ISOLATION: Strict exclusion of role fields to block escalation.
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

export class SignupDto {
  
  @ApiProperty({ 
    example: 'Radouane', 
    description: 'First name of the applicant. Strips HTML and leading/trailing spaces.' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * INGRESS SANITIZATION:
   * Prevents Persistent XSS by stripping script/HTML tags at the ingress point.
   */
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value
  )
  firstName: string;

  @ApiProperty({ 
    example: 'Djoudi', 
    description: 'Family name of the applicant. Normalized for B-Tree indexing.' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * DATA NORMALIZATION:
   * Standardizes family names to maintain consistency in searching and reporting.
   */
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value
  )
  familyName: string;

  @ApiProperty({ 
    example: '+213661234567', 
    description: 'ITU-T E.164 compliant phone number (Algeria/DZ).' 
  })
  @IsPhoneNumber('DZ') 
  @IsNotEmpty()
  /**
   * WHITESPACE CLEANING:
   * Ensures consistent storage by removing all internal spaces from the phone string.
   */
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().replace(/\s/g, '') : value
  )
  phoneNumber: string;

  @ApiProperty({ 
    example: 'contact@zenith-systems.dz', 
    description: 'Primary unique identity key. Enforced in the persistence layer.' 
  })
  @IsEmail({}, { message: 'SECURITY_ALERT: Malformed email structure detected.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  email: string;

  @ApiProperty({ 
    example: 'Znt@2026!Sec', 
    description: 'High-entropy password. Requires: [A-Z], [a-z], [0-9], and Special Chars.' 
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  /**
   * CRYPTOGRAPHIC ENTROPY ENFORCEMENT:
   * Validates complexity requirements to prevent dictionary and brute-force attacks.
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'SECURITY_POLICY: Password complexity requirements not met (10-32 chars, diverse sets).',
  })
  password: string;

  /**
   * SECURITY ARCHITECTURE NOTE:
   * The 'role' field is omitted by design. Authorization occurs in the AuthService
   * using the Dynamic RBAC bootstrap to assign the 'USER' role by default.
   */
}