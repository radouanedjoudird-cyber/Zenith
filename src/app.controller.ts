import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { Public } from './common/decorators/public.decorator';

/**
 * ZENITH ROOT GATEWAY CONTROLLER - v7.3.0
 * ---------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURAL ROLE:
 * Serves as the primary entry point and health-check responder for Zenith.
 * * * SECURITY STRATEGY: 
 * 1. PUBLIC_ACCESS: Marked to bypass Global Auth Guards for infra monitoring.
 * 2. STANDARDIZED_INGRESS: Ensures root probes get consistent JSON responses.
 */
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * ROOT_HEALTH_CHECK
   * -----------------
   * Responds to infrastructure probes (K8s/Nginx/Load Balancers).
   * @Route   GET /
   * @Access  Public
   */
  @Public()
  @Get()
  @HttpCode(HttpStatus.OK)
  getSystemStatus(): object {
    /**
     * DELEGATION:
     * Offloading core status aggregation to the AppService for better testability.
     */
    return this.appService.getSystemStatus();
  }
}