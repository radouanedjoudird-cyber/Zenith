import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString, Matches, MaxLength, MinLength
} from 'class-validator';
import { Role } from '../../common/enums/role.enum';

/**
 * DATA TRANSFER OBJECT: SIGNUP PROTOCOL
 * ------------------------------------
 * SECURITY MEASURES:
 * 1. Sanitization: Strips malicious HTML tags (XSS Prevention).
 * 2. Normalization: Standardizes email and name casings for DB consistency.
 * 3. Validation: Enforces regional phone formats and complex password entropy.
 */
export class SignupDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  // XSS PROTECTION: Prevents script injection in user-facing fields
  @Transform(({ value }) => value?.trim().replace(/<[^>]*>?/gm, ''))
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  // DATA CONSISTENCY: Enforces lowercase storage for predictable querying
  @Transform(({ value }) => value?.trim().toLowerCase().replace(/<[^>]*>?/gm, ''))
  familyName: string;

  @IsPhoneNumber('DZ') // Regional constraint for Algerian telecommunications
  @IsNotEmpty()
  @Transform(({ value }) => value?.trim().replace(/\s/g, ''))
  phoneNumber: string;

  @IsEmail()
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => value?.trim().toLowerCase())
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  /**
   * CRYPTOGRAPHIC PASSWORD POLICY (Regex):
   * Ensures high-entropy strings containing:
   * [Uppercase, Lowercase, Digit, Special Character]
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'Security Policy: Password must include Uppercase, Lowercase, Number, and Special Symbol.',
  })
  password: string;

  /**
   * OPTIONAL ROLE CLAIM:
   * Clients may request a role, but it is subject to 'Privilege Filter' in AuthService.
   */
  @IsEnum(Role)
  @IsOptional()
  role?: Role = Role.USER;
}