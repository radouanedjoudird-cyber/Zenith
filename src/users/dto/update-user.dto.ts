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
 * UPDATE USER DATA TRANSFER OBJECT (DTO)
 * --------------------------------------
 * This class defines the schema for partial user updates.
 * All fields are optional (@IsOptional) to support PATCH requests.
 */
export class UpdateUserDto {
  /**
   * SECURITY: Sanitizes input to prevent XSS (Cross-Site Scripting).
   * Removes any HTML tags and trims whitespace.
   */
  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Transform(({ value }) => value?.trim().replace(/<[^>]*>?/gm, ''))
  firstName?: string;

  /**
   * NORMALIZATION: Converts family name to lowercase for database consistency.
   */
  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Transform(({ value }) => value?.trim().toLowerCase().replace(/<[^>]*>?/gm, ''))
  familyName?: string;

  /**
   * VALIDATION: Ensures the phone number follows Algerian ('DZ') standards.
   * Trims whitespace to prevent format mismatch.
   */
  @IsOptional()
  @IsPhoneNumber('DZ')
  @Transform(({ value }) => value?.trim().replace(/\s/g, ''))
  phoneNumber?: string;

  /**
   * DATA INTEGRITY: Forces email to lowercase to prevent duplicate accounts 
   * caused by case sensitivity (e.g., User@Email.com vs user@email.com).
   */
  @IsOptional()
  @IsEmail()
  @MaxLength(100)
  @Transform(({ value }) => value?.trim().toLowerCase())
  email?: string;

  /**
   * SECURITY POLICY: Enforces a high-entropy password.
   * Must include: Uppercase, Lowercase, Number, and Special Character.
   * Length: 10 to 32 characters.
   */
  @IsOptional()
  @IsString()
  @MinLength(10)
  @MaxLength(32)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/,
    {
      message: 'Security Policy: Password must include Uppercase, Lowercase, Number, and Special Symbol.',
    },
  )
  password?: string;
}