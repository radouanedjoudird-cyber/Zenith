import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

/**
 * SECURE SIGNUP DTO - ZENITH CLOUD
 * SECURITY STRATEGY:
 * 1. Data Normalization: Trimming and lowercasing to prevent injection and duplicates.
 * 2. Strict RegEx: Enforcing complex patterns for passwords and names.
 * 3. Payload Hardening: Strict length limits to mitigate Buffer Overflow/DoS.
 */
export class SignupDto {
  
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * SANITIZATION:
   * Remove any HTML/Script tags and trim spaces to prevent XSS.
   */
  @Transform(({ value }) => value?.trim().replace(/<[^>]*>?/gm, ''))
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  @Transform(({ value }) => value?.trim().toLowerCase().replace(/<[^>]*>?/gm, ''))
  familyName: string;

  @IsPhoneNumber('DZ')
  /**
   * SECURITY: Normalize phone format to prevent character injection.
   */
  @Transform(({ value }) => value?.trim().replace(/\s/g, ''))
  phoneNumber: string;

  @IsEmail()
  @IsNotEmpty()
  @MaxLength(100)
  /**
   * NORMALIZATION:
   * Force lowercase to prevent account duplication via case variation (e.g., User@Zenith vs user@zenith).
   */
  @Transform(({ value }) => value?.trim().toLowerCase())
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(10) // Increased for higher security
  @MaxLength(32)
  /**
   * SECURE PASSWORD REGEX:
   * Requires: 1 Uppercase, 1 Lowercase, 1 Number, and 1 Special Character.
   * This mitigates Dictionary and Brute Force attacks.
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$/, {
    message: 'Security Policy: Password is too weak.',
  })
  password: string;
}
