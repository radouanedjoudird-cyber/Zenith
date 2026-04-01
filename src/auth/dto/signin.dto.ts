import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator';

/**
 * SECURE SIGNIN DTO
 * Handles strict validation and sanitization for Zenith Cloud.
 * SECURITY STRATEGY:
 * 1. Input Sanitization: Trim and Lowercase to prevent duplication/bypass.
 * 2. Payload Hardening: Strict length limits to prevent DoS.
 * 3. Pattern Matching: Ensure no malicious scripts are injected via fields.
 */
export class SigninDto {
  
  @IsEmail({}, { message: 'Invalid credentials format' }) // Generic message
  @IsNotEmpty()
  @MaxLength(100)
  /**
   * SANITIZATION:
   * Trims whitespace and converts to lowercase before validation.
   * Prevents "Case Sensitivity" bypass attacks.
   */
  @Transform(({ value }) => value?.trim().toLowerCase())
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(32)
  /**
   * SECURITY PATTERN:
   * Prevents common injection characters while allowing strong passwords.
   */
  @Matches(/^[a-zA-Z0-9!@#$%^&*()_+.\-]*$/, {
    message: 'Password contains prohibited characters',
  })
  password: string;
}