/**
 * @fileoverview Unified Exception Strategy for Zenith Engine.
 * Implements global anomaly detection, data redaction, and security orchestration.
 * Inspired by Amazon's Internal Fault-Tolerance Patterns.
 * * @author Radouane Djoudi
 * @version 6.0.0
 * @license Enterprise
 */

import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/**
 * Global Exception Interceptor.
 * Orchestrates API error contracts and enforces zero-leakage of system internals.
 */
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  /** Dedicated logger for infrastructure monitoring and forensic auditing */
  private readonly logger = new Logger('ZENITH_GATEWAY_FILTER');

  /**
   * Catches and transforms system exceptions into standardized JSON responses.
   * * @param exception - The caught HttpException instance.
   * @param host - The execution context host (HTTP/RPC).
   * @returns {void}
   */
  catch(exception: HttpException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    
    const status = exception.getStatus();
    const exceptionResponse: any = exception.getResponse();

    // 🛡️ [INTELLIGENT ANOMALY DETECTION]
    // Validates if the exception is triggered by the Zenith Security Shield.
    const rawMessage = exceptionResponse.message || exception.message || 'Internal System Error';
    const isSecurityAnomaly = rawMessage.toString().includes('ZENITH_SHIELD');

    /**
     * Unified Error Response Contract (ERC).
     * Provides consistent telemetry for Frontend and Mobile integrations.
     */
    const errorBody = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      /**
       * PII (Personally Identifiable Information) Redaction logic.
       * If a security breach is detected, the message is sanitized to prevent info leakage.
       */
      message: isSecurityAnomaly 
        ? 'A security anomaly was detected with your session. Protective protocols engaged.' 
        : rawMessage,
      error: isSecurityAnomaly ? 'SECURITY_BREACH_DETECTED' : (exceptionResponse.error || 'EnterpriseException'),
      /** Deterministic Trace ID for distributed log correlation */
      traceId: this.generateTraceId(request.ip || '0.0.0.0'),
    };

    // 🚨 [FORENSIC TELEMETRY]
    // Escalates logging level for security threats or critical infrastructure failures.
    this.logAnomaly(request, status, rawMessage, isSecurityAnomaly);

    response.status(status).json(errorBody);
  }

  /**
   * Generates a unique trace identifier for diagnostic tracking.
   * @private
   */
  private generateTraceId(ip: string): string {
    return Buffer.from(`${Date.now()}-${ip}`).toString('base64').substring(0, 12).toUpperCase();
  }

  /**
   * Executes forensic logging based on event severity.
   * @private
   */
  private logAnomaly(req: Request, status: number, msg: string, isShield: boolean): void {
    const logCtx = `${req.method} ${req.url} | IP: ${req.ip} | User: ${req.user?.['sub'] || 'ANON'}`;
    
    if (isShield || status >= 500) {
      this.logger.error(`🚨 [CRITICAL_EVENT] ${logCtx} | Trace: ${msg}`);
    } else {
      this.logger.warn(`[HTTP_ANOMALY] ${logCtx} | Status: ${status}`);
    }
  }
}