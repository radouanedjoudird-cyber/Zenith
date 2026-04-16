/**
 * @fileoverview Specialized Security Exception Filter for Zenith.
 * Dedicated to capturing and neutralizing session hijacking and identity anomalies.
 * Inspired by Netflix's "Chao" Security Patterns and Zero-Trust Architectures.
 * * @author Radouane Djoudi
 * @version 6.0.0
 * @security Level-4 Implementation
 */

import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    ForbiddenException,
    HttpStatus,
    Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/**
 * SecurityBreachFilter intercepts ForbiddenExceptions specifically tagged as security anomalies.
 * It ensures that attackers receive no technical insights while forensic teams get full telemetry.
 */
@Catch(ForbiddenException)
export class SecurityBreachFilter implements ExceptionFilter {
  /** Infrastructure logger with 'SECURITY_SHIELD' context for SIEM integration */
  private readonly logger = new Logger('ZENITH_SECURITY_SHIELD');

  /**
   * Intercepts ForbiddenExceptions and checks for hardware-identity mismatch.
   * * @param exception - The caught ForbiddenException.
   * @param host - Execution context for the current request.
   */
  catch(exception: ForbiddenException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    
    const status = exception.getStatus();
    const exceptionResponse: any = exception.getResponse();
    const message = exceptionResponse.message || exception.message;

    // 🛡️ [HIGH-LEVEL DISCRIMINATOR]
    // Identifies if this is a standard 403 or a critical Zenith Shield anomaly.
    const isSecurityShieldTriggered = message.toString().includes('ZENITH_SHIELD');

    // If it's a standard forbidden error (not a shield trigger), skip this filter
    if (!isSecurityShieldTriggered) {
      this.handleStandardForbidden(response, request, status, message);
      return;
    }

    /**
     * BREACH RESPONSE PROTOCOL:
     * 1. Forensic Logging: Captures IP, User ID, and Device Context.
     * 2. Identity Redaction: Replaces detailed error with a generic safety message.
     * 3. Response Standardization: Returns a 403 with a custom Security Error Code.
     */
    this.executeForensicLogging(request, message);

    response.status(HttpStatus.FORBIDDEN).json({
      success: false,
      statusCode: HttpStatus.FORBIDDEN,
      timestamp: new Date().toISOString(),
      path: request.url,
      /**
       * OBFUSCATION: We return a generic message to the client to prevent 
       * revealing our internal detection logic to potential attackers.
       */
      message: 'Account protection protocols engaged. Your session has been terminated for security reasons.',
      error: 'SECURITY_INTEGRITY_VIOLATION',
      protection_id: this.generateProtectionId()
    });
  }

  /**
   * Logs critical security events with full context for forensic investigation.
   * @private
   */
  private executeForensicLogging(req: Request, rawMsg: string): void {
    const userId = req.user?.['sub'] || 'UNAUTHENTICATED';
    const metadata = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.url,
      method: req.method
    };

    this.logger.error(
      `🚨 [SECURITY_BREACH] Attempt detected! Identity: ${userId} | Device Trace: ${metadata.userAgent} | IP: ${metadata.ip} | Reason: ${rawMsg}`
    );
  }

  /**
   * Handles standard Forbidden responses without security obfuscation.
   * @private
   */
  private handleStandardForbidden(res: Response, req: Request, status: number, msg: string): void {
    res.status(status).json({
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: req.url,
      message: msg,
      error: 'ForbiddenAccess'
    });
  }

  /**
   * Generates a non-deterministic ID for customer support reference.
   * @private
   */
  private generateProtectionId(): string {
    return `PROT-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
  }
}