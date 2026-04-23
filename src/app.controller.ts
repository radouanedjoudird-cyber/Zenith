/**
 * ============================================================================
 * ZENITH GLOBAL INGRESS GATEWAY
 * ============================================================================
 * @module AppController
 * @version 7.4.0
 * @description Primary entry point for infrastructure probes and system discovery.
 * * * DESIGN PRINCIPLES:
 * 1. ZERO_TRUST_BYPASS: Explicitly public for health-monitoring orchestration.
 * 2. STANDARDIZED_RESPONSE: Follows the Zenith System Registry (ZSR) protocol.
 * ============================================================================
 */

import { Controller, Get, HttpCode, HttpStatus, Logger } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';
import { Public } from './common/decorators/public.decorator';

@ApiTags('Kernel & Registry')
@Controller()
export class AppController {
  private readonly logger = new Logger('ZENITH_GATEWAY');

  constructor(private readonly appService: AppService) {}

  /**
   * @function getSystemStatus
   * @description Dispatches core kernel state for load balancers and root probes.
   * @access PUBLIC
   * @route GET / (Root)
   * @note This bypasses Global Prefix if configured in main.ts correctly.
   */
  @Public()
  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Core Kernel Heartbeat', 
    description: 'Direct access to kernel status for infrastructure uptime monitoring.' 
  })
  @ApiResponse({ status: 200, description: 'Zenith Kernel is alive.' })
  getSystemStatus(): object {
    this.logger.log('🛡️ [HEALTH_CHECK] Root gateway reached. Status: OPERATIONAL');
    return this.appService.getSystemStatus();
  }

  /**
   * @function getApiRegistry
   * @description Standardized API metadata endpoint within the v1 namespace.
   * @access PUBLIC
   * @route GET /api/v1/status
   */
  @Public()
  @Get('status') 
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'API Registry Status',
    description: 'Retrieves system metadata within the API versioning scope.' 
  })
  @ApiResponse({ status: 200, description: 'Registry data retrieved successfully.' })
  getApiRegistry(): object {
    return this.appService.getSystemStatus();
  }
}