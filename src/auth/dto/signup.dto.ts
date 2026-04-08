import { Role } from '@prisma/client'; // HIGH PERFORMANCE: Direct DB Type Sync
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator';

/**
 * DATA TRANSFER OBJECT: SIGNUP PROTOCOL
 * ------------------------------------
 * SECURITY MEASURES:
 * 1. Sanitization: Strips malicious HTML tags (XSS Prevention) using high-speed Regex.
 * 2. Normalization: Standardizes email and name casings for DB consistency.
 * 3. Validation: Enforces regional phone formats (DZ) and complex password entropy.
 * 4. DB Integrity: Strictly typed using Prisma Client Roles.
 */
export class SignupDto {
  
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * XSS PROTECTION & WHITESPACE CLEANUP:
   * Standardizes the user input for Infrastructure-grade stability.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value)
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  /**
   * DATA CONSISTENCY & NORMALIZATION:
   * Enforces lowercase storage for predictable querying and indexing performance.
   */
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase().replace(/<[^>]*>?/gm, '') : value)
  familyName: string;

  /**
   * REGIONAL VALIDATION (ALGERIA - DZ):
   * Ensures the phone number complies with local telecommunication standards.
   * Strips all internal whitespaces for optimized DB storage.
   */
  @IsPhoneNumber('DZ') 
  @IsNotEmpty()
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/\s/g, '') : value)
  phoneNumber: string;

  @IsEmail({}, { message: 'Security Alert: Invalid email structure detected.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  /**
   * CRYPTOGRAPHIC PASSWORD POLICY (MIL-SPEC ENTROPY):
   * Enforces a minimum length of 10 and requires:
   * [1 Uppercase, 1 Lowercase, 1 Digit, 1 Special Character (@$!%*?&_#^())]
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'Security Policy Failure: Password must contain Uppercase, Lowercase, Number, and Special Character.',
  })
  password: string;

  /**
   * AUTHORIZATION CLAIM:
   * Defaults to USER. Elevation to ADMIN requires distinct privilege verification in AuthService.
   */
  @IsEnum(Role)
  @IsOptional()
  role?: Role = Role.USER;
}