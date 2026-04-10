import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';

/**
 * DATA TRANSFER OBJECT: SIGNIN PROTOCOL (SHIELDED)
 * -----------------------------------------------
 * ARCHITECTURE: Enterprise Secure Access Gateway
 * * SECURITY MEASURES:
 * 1. ANTI-ENUMERATION: Generic error messaging to mitigate account harvesting.
 * 2. PAYLOAD NORMALIZATION: Canonical email formatting to ensure DB index hits.
 * 3. INJECTION PREVENTION: Whitelist regex enforcement on password stream.
 * * @author Radouane Djoudi
 * @project Zenith Secure Engine
 */
export class SigninDto {

  @ApiProperty({ 
    example: 'admin@zenith-systems.dz', 
    description: 'Registered email address. Case-insensitive.' 
  })
  /**
   * CREDENTIAL NORMALIZATION:
   * Forces lowercase to ensure consistency with the DB unique index.
   * Generic error message prevents 'Account Discovery' attacks.
   */
  @IsEmail({}, { message: 'Authentication failed: Invalid credentials.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
  email: string;

  @ApiProperty({ 
    example: 'Znt@2026!Sec', 
    description: 'Cryptographic password string.' 
  })
  /**
   * SYMMETRIC VALIDATION:
   * Aligned with Signup entropy but utilizes a generic message.
   * Whitelisting allowed characters to block complex injection payloads.
   */
  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  @Matches(/^[A-Za-z\d@$!%*?&_#^()]*$/, {
    message: 'Authentication failed: Invalid credentials.',
  })
  password: string;
}