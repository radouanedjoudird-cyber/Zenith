import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';

/**
 * DATA TRANSFER OBJECT: SIGNIN PROTOCOL (SHIELDED)
 * -----------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * SECURITY STRATEGY:
 * 1. ANTI-ENUMERATION: Generic error messaging to mitigate account harvesting.
 * 2. PAYLOAD_NORMALIZATION: Canonical email formatting for high-speed DB index hits.
 * 3. INJECTION_PREVENTION: Strict regex whitelisting on the password stream.
 */
export class SigninDto {

  @ApiProperty({ 
    example: 'admin@zenith-systems.dz', 
    description: 'Registered identity email. Case-insensitive.' 
  })
  /**
   * CREDENTIAL NORMALIZATION:
   * Trims and lowercases the input before validation to ensure it matches
   * the unique index in the 'users' table.
   */
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail({}, { message: 'Authentication failed: Invalid credentials.' })
  @IsNotEmpty()
  @MaxLength(100)
  email: string;

  @ApiProperty({ 
    example: 'Znt@2026!Sec', 
    description: 'Cryptographic password string.' 
  })
  /**
   * ENTROPY & INJECTION CONTROL:
   * Aligned with signup complexity. The regex blocks common SQLi and XSS payloads
   * by restricting characters to a secure set.
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