import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { Public } from './common/decorators/public.decorator';

/**
 * ZENITH ROOT GATEWAY CONTROLLER - v1.1
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Serves as the primary entry point and health-check responder for Zenith.
 * * * SECURITY STRATEGY: 
 * 1. MINIMAL_DISCLOSURE: Strips technical metadata from the root response.
 * 2. EXPLICIT_TYPING: Enforces standardized JSON schema for all ingress points.
 * 3. PUBLIC_ACCESS: Explicitly marked to bypass Global Auth Guards for monitoring.
 */
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * ROOT_HEALTH_CHECK
   * -----------------
   * Responds to infrastructure probes (Nginx/Load Balancers).
   * @Route   GET /
   * @Access  Public
   */
  @Public() // MANDATORY: Allows health probes to hit the endpoint without a JWT
  @Get()
  @HttpCode(HttpStatus.OK)
  getHello(): { status: string; message: string; timestamp: string } {
    /**
     * SECURITY ENFORCEMENT: 
     * We return a standardized JSON structure. This prevents "Leaky Responses" 
     * where server signatures or framework versions might be exposed to 
     * automated scanning tools.
     */
    return {
      status: 'active',
      message: 'Zenith Secure API is operational.',
      timestamp: new Date().toISOString(), // Vital for cross-system latency checks
    };
  }
}