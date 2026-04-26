/**
 * ============================================================================
 * ZENITH IDENTITY & ACCESS MANAGEMENT - RECOVERY SIGNALING PROTOCOL
 * ============================================================================
 * @module RequestRecoveryDto
 * @version 7.4.0
 * @description Data Transfer Object for initiating the secure identity recovery lifecycle.
 * * ARCHITECTURAL RATIONALE:
 * 1. ANTI_ENUMERATION: Optimized for services implementing non-descriptive responses.
 * 2. CANONICAL_NORMALIZATION: Enforces lowercase email mapping for precise DB lookups.
 * ============================================================================
 */

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator';

/**
 * @class RequestRecoveryDto
 * @description Ingress payload for the Recovery Token Request (RTR) stage.
 */
export class RequestRecoveryDto {
  
  /**
   * The primary identity key (email) targeted for credential restoration.
   * @type {string}
   * @security NORMALIZATION: Canonical lowercase transformation to prevent case-sensitivity bypass.
   * @validation ISO_EMAIL: Enforces RFC 5322 compliance.
   */
  @ApiProperty({ 
    example: 'contact@zenith-systems.dz', 
    description: 'The registered email address for account restoration.' 
  })
  @IsEmail({}, { message: 'SECURITY_ALERT: Malformed identity sequence detected.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => 
    typeof value === 'string' ? value.trim().toLowerCase() : value
  )
  email: string;

}