import { ApiPropertyOptional } from '@nestjs/swagger';
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
 * DATA TRANSFER OBJECT: USER UPDATE PROTOCOL (SHIELDED)
 * ----------------------------------------------------
 * STRATEGY: Zero-Trust Partial Updates
 * * SECURITY MEASURES:
 * 1. MASS ASSIGNMENT PROTECTION: Strictly limits fields to non-privileged attributes.
 * 2. TYPE-SAFE SANITIZATION: Prevents XSS and injection via rigorous @Transform guards.
 * 3. SWAGGER ADAPTATION: Utilizes @ApiPropertyOptional for accurate frontend contract.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
export class UpdateUserDto {

  @ApiPropertyOptional({ 
    example: 'Radouane', 
    description: 'Updated first name. Strips HTML and trims whitespace.' 
  })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/<[^>]*>?/gm, '') : value)
  firstName?: string;

  @ApiPropertyOptional({ 
    example: 'Djoudi', 
    description: 'Updated family name. Normalized to lowercase for indexing.' 
  })
  @IsOptional()
  @IsString()
  @MaxLength(50)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase().replace(/<[^>]*>?/gm, '') : value)
  familyName?: string;

  @ApiPropertyOptional({ 
    example: '+213661234567', 
    description: 'Updated phone number in DZ regional format.' 
  })
  @IsOptional()
  @IsPhoneNumber('DZ')
  @Transform(({ value }) => typeof value === 'string' ? value.trim().replace(/\s/g, '') : value)
  phoneNumber?: string;

  @ApiPropertyOptional({ 
    example: 'new-contact@zenith.dz', 
    description: 'New email address. Note: This may trigger re-verification.' 
  })
  @IsOptional()
  @IsEmail({}, { message: 'Security Alert: Malformed email structure detected.' })
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
  email?: string;

  @ApiPropertyOptional({ 
    example: 'Znt@2026!Update', 
    description: 'New high-entropy password. Recommended to use a dedicated endpoint.' 
  })
  @IsOptional()
  @IsString()
  @MinLength(10)
  @MaxLength(32)
  /**
   * SECURITY POLICY ENFORCEMENT:
   * Even in updates, we never compromise on entropy.
   */
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#^()])[A-Za-z\d@$!%*?&_#^()]{10,32}$/,
    {
      message: 'Security Policy: Password must maintain Mil-Spec complexity.',
    },
  )
  password?: string;

  /**
   * ARCHITECTURAL SAFEGUARD:
   * Fields like 'id', 'role', 'isVerified', and 'createdAt' are EXCLUDED.
   * Any attempt to inject them will be stripped by the ValidationPipe.
   */
}