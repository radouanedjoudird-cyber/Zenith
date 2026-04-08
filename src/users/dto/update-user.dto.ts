import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsOptional,
  IsPhoneNumber,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

/**
 * ZENITH UPDATE USER DTO - SECURE PATCH PROTOCOL
 * ---------------------------------------------
 * STRATEGY: 
 * 1. Partial Updates: All fields are @IsOptional to support efficient PATCH operations.
 * 2. Hardened Sanitization: Integrated Type-Guards in @Transform to prevent runtime crashes.
 * 3. Scope Limitation: Noticeably excludes 'Role' to prevent Horizontal Privilege Escalation.
 */
export class UpdateUserDto {

  @IsOptional()
  @IsString()
  @MaxLength(50)
  /**
   * XSS DEFENSE LAYER:
   * Strips HTML and trims whitespace. 
   * Type-check ensures compatibility with non-string payloads.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  /**
   * DATA NORMALIZATION:
   * Enforces lowercase storage for consistent lookups and indexing.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase().replace(/<[^>]*>?/gm, '') : value)
  familyName?: string;

  @IsOptional()
  @IsPhoneNumber('DZ')
  /**
   * INFRASTRUCTURE CONSISTENCY:
   * Strips internal spaces to match the storage format used in Zenith Registry.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/\s/g, '') : value)
  phoneNumber?: string;

  /**
   * CRITICAL SECURITY NOTE: 
   * Updating email via this DTO should be paired with an 'Email Verification' flow 
   * in the UserService to prevent account takeover.
   */
  @IsOptional()
  @IsEmail({}, { message: 'Security Alert: Invalid email format submitted.' })
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
  email?: string;

  @IsOptional()
  @IsString()
  @MinLength(10)
  @MaxLength(32)
  /**
   * MIL-SPEC PASSWORD COMPLEXITY:
   * Enforced even on partial updates to ensure no weak passwords enter the system.
   */
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/,
    {
      message: 'Security Policy: Password must include Uppercase, Lowercase, Number, and Special Symbol.',
    },
  )
  password?: string;
}