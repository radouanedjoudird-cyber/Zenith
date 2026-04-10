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
 * DATA TRANSFER OBJECT: SIGNUP PROTOCOL (SHIELDED EDITION)
 * --------------------------------------------------------
 * ARCHITECTURE: Enterprise Secure Identity Management
 * * SECURITY MEASURES:
 * 1. XSS MITIGATION: High-speed Regex stripping for HTML injection prevention.
 * 2. DATA NORMALIZATION: Canonical form enforcement (lowercase/trimmed) for DB indexing.
 * 3. CRYPTOGRAPHIC ENTROPY: Minimum 10-char password with multi-class character requirements.
 * 4. PRIVILEGE ISOLATION: Role field is strictly excluded to prevent unauthorized elevation.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
export class SignupDto {
  
  @ApiProperty({ 
    example: 'Radouane', 
    description: 'First name of the applicant. Strips HTML tags and leading/trailing spaces.' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * INGRESS SANITIZATION:
   * Prevents persistent XSS by stripping potential script tags before they reach the DB layer.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value)
  firstName: string;

  @ApiProperty({ 
    example: 'Djoudi', 
    description: 'Family name of the applicant. Normalized to lowercase for search optimization.' 
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * CANONICAL NORMALIZATION:
   * Standardizes family names to lowercase to prevent duplicate entries and optimize B-Tree indexing.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase().replace(/<[^>]*>?/gm, '') : value)
  familyName: string;

  @ApiProperty({ 
    example: '+213661234567', 
    description: 'ITU-T E.164 compliant phone number for Algeria (DZ).' 
  })
  @IsPhoneNumber('DZ') 
  @IsNotEmpty()
  /**
   * SPACE STRIPPING:
   * Cleans internal whitespaces to ensure consistent storage in the Infrastructure layer.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/\s/g, '') : value)
  phoneNumber: string;

  @ApiProperty({ 
    example: 'contact@zenith-systems.dz', 
    description: 'Unique identifier for communication and authentication.' 
  })
  @IsEmail({}, { message: 'Security Alert: Malformed email structure detected.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
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
   * MIL-SPEC ENTROPY ENFORCEMENT:
   * Regex validates for Upper, Lower, Number, and Special character sets.
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'Security Policy Failure: Password complexity (10-32 chars, mix of types) not met.',
  })
  password: string;

  /**
   * NOTE ON AUTHORIZATION:
   * The 'role' field is intentionally OMITTED from SignupDto.
   * All new identities are defaulted to USER in the Service layer.
   * Privilege escalation is handled via an audited Administrative Endpoint.
   */
}