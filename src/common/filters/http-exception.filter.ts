import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    HttpException,
    Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/**
 * ZENITH UNIFIED ERROR RESPONSE ENGINE
 * ------------------------------------
 * SECURITY: Prevents internal stack trace leakage.
 * CONSISTENCY: Enforces a single JSON structure for all API errors.
 */
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('HTTP_ERROR');

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse: any = exception.getResponse();

    const errorBody = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message: exceptionResponse.message || exception.message || 'Internal Server Error',
      error: exceptionResponse.error || 'Unknown Error',
    };

    // SYSTEM AUDIT: Log the error for infrastructure monitoring
    this.logger.error(
      `${request.method} ${request.url} - Status: ${status} - Msg: ${errorBody.message}`
    );

    response.status(status).json(errorBody);
  }
}