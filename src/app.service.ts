import { Injectable, Logger } from '@nestjs/common';

/**
 * SECURE APP SERVICE
 * Handles core application-level logic.
 * SECURITY STRATEGY:
 * 1. Centralized Logging: Monitor service health internally.
 * 2. Minimalist Output: Avoid leaking system status or versioning to the public.
 */
@Injectable()
export class AppService {
  private readonly logger = new Logger(AppService.name);

  /**
   * GET HELLO
   * Returns a standard operational status.
   */
  getHello(): string {
    /**
     * SECURITY: We use a neutral, professional message.
     * In production, this can be used by Load Balancers (like Nginx)
     * to check if the service is alive without exposing internal details.
     */
    this.logger.log('Health check: Root endpoint accessed.');
    
    return 'Zenith Cloud API: Operational';
  }
}
