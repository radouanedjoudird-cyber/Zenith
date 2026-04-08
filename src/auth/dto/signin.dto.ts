import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';

/**
 * DATA TRANSFER OBJECT: SIGNIN PROTOCOL
 * ------------------------------------
 * SECURITY MEASURES:
 * 1. Anti-Enumeration: Standardized error messages to mask user existence.
 * 2. Payload Normalization: Forced lowercase and trimming for predictable DB lookups.
 * 3. Character Symmetry: Strict alignment with Signup entropy policies.
 */
export class SigninDto {

  /**
   * SECURITY: Generic error message prevents 'Email Enumeration' discovery.
   * PERFORMANCE: Forced lowercasing to match DB indexes (email_unique).
   */
  @IsEmail({}, { message: 'Invalid email or password format.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
  email: string;

  /**
   * CRYPTOGRAPHIC CONSISTENCY:
   * Ensures the characters sent match the allowed set defined in SignupDto.
   * This prevents 'WAF Bypass' attempts or injection of forbidden control characters.
   */
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  @Matches(/^[A-Za-z\d@$!%*?&_#^()]*$/, {
    message: 'Invalid email or password format.',
  })
  password: string;
}