import { Transform } from 'class-transformer';
import {
  IsEmail, IsNotEmpty,
  IsPhoneNumber,
  IsString, Matches, MaxLength, MinLength
} from 'class-validator';

export class SignupDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  // XSS PROTECTION: Strips HTML tags to prevent script injection in name fields
  @Transform(({ value }) => value?.trim().replace(/<[^>]*>?/gm, ''))
  firstName: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  // NORMALIZATION: Ensures family name is trimmed and lowercase for DB consistency
  @Transform(({ value }) => value?.trim().toLowerCase().replace(/<[^>]*>?/gm, ''))
  familyName: string;

  @IsPhoneNumber('DZ') // Regional validation for Algeria
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
   * IRONCLAD PASSWORD POLICY (Regex):
   * 1. Requires at least one lowercase letter (?=.*[a-z])
   * 2. Requires at least one uppercase letter (?=.*[A-Z])
   * 3. Requires at least one numeric digit (?=.*\d)
   * 4. Requires one special symbol from allowed set (?=.*[@$!%*?&_#^()])
   */
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/, {
    message: 'Security Policy: Password must include Uppercase, Lowercase, Number, and Special Symbol.',
  })
  password: string;
}