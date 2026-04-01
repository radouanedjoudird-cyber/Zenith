import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';

/**
 * SECURE ROOT CONTROLLER
 * This controller handles the entry point of the Zenith API.
 * SECURITY STRATEGY: 
 * 1. Minimize information disclosure (No versioning or tech stack info in response).
 * 2. Explicit HTTP status codes.
 */
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * @Route   GET /
   * @Desc    Health check or Landing point
   * @Access  Public
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  getHello(): { status: string; message: string } {
    /**
     * SECURITY: Instead of returning a raw string or server details, 
     * we return a generic JSON object. This prevents scanners from 
     * easily identifying the underlying technology via simple text parsing.
     */
    return {
      status: 'active',
      message: 'Zenith Secure API is operational.'
    };
  }
}