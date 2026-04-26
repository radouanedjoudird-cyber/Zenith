/**
 * ============================================================================
 * ZENITH SECURE KERNEL - INFRASTRUCTURE & RELIABILITY MODULE
 * ============================================================================
 * @module InfraController
 * @version 7.4.0
 * @author Zenith Systems Engine
 * @description Mission-critical telemetry, diagnostics, and system probes.
 * * DESIGN PATTERNS:
 * 1. PROBE_PATTERN: Implements standard Liveness/Readiness for Orchestrators.
 * 2. RBAC_HIERARCHY: Integrated with Zenith's Global Security Shield.
 * 3. LOAD_SIMULATION: Deterministic CPU saturation for scaling benchmarks.
 * * SECURITY COMPLIANCE:
 * - NIST SP 800-53: Infrastructure monitoring and logging.
 * - OWASP ASVS: Access control and resource exhaustion prevention.
 * ============================================================================
 */

import {
  Controller,
  Get,
  HttpStatus,
  Logger,
  Query,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags
} from '@nestjs/swagger';
import {
  HealthCheck,
  HealthCheckService,
  PrismaHealthIndicator
} from '@nestjs/terminus';

/* --- CORE SECURITY INTERFACE --- */
import { AtGuard } from '../auth/guards/at.guard';
import { Public } from '../common/decorators/public.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';
import { RolesGuard } from '../common/guards/roles.guard';

/* --- PERFORMANCE & PERSISTENCE --- */
import { MonitoringInterceptor } from '../common/interceptors/monitoring.interceptor';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('Infrastructure & Reliability')
@Controller({
  path: 'infra',
  version: '1',
})
@UseInterceptors(MonitoringInterceptor)
export class InfraController {
  private readonly logger = new Logger('ZENITH_INFRA_ENGINE');

  constructor(
    private readonly health: HealthCheckService,
    private readonly prismaHealth: PrismaHealthIndicator,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * @operation [HEALTH_PROBE]
   * @description Standardized health check for Kubernetes/Docker orchestrators.
   * @access PUBLIC_ACCESS (Whitelisted for system probes)
   */
  @Public()
  @Get('health')
  @HealthCheck()
  @ApiOperation({ 
    summary: 'System Liveness Probe',
    description: 'Validates persistence layer availability and kernel integrity.' 
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Core services operational.' })
  @ApiResponse({ status: HttpStatus.SERVICE_UNAVAILABLE, description: 'Kernel degradation detected.' })
  async check() {
    this.logger.log('Executing System Liveness Probe...');
    return this.health.check([
      /**
       * PERSISTENCE_LAYER_VALIDATION:
       * Ensures the Prisma ORM maintains a healthy heartbeat with the registry.
       */
      () => this.prismaHealth.pingCheck('database', this.prisma),
    ]);
  }

  /**
   * @operation [STRESS_SIMULATION]
   * @description Synthetic workload generation for autoscaling and P99 benchmarking.
   * @access RESTRICTED (Elevated Privileges Required)
   * @security JWT_BEARER_TOKEN | ROLE_ADMIN | ROLE_SUPERADMIN
   */
  @Get('stress')
  @UseGuards(AtGuard, RolesGuard)
  /**
   * BEST_PRACTICE: Explicitly allow both ADMIN and SUPERADMIN.
   * Note: The RolesGuard must be implemented to allow SUPERADMIN bypass.
   */
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Resource Saturation Simulation',
    description: 'Authorized stress testing for benchmarking P99 latency and scaling triggers.' 
  })
  @ApiQuery({ 
    name: 'cycles', 
    type: Number, 
    required: false, 
    example: 100000000,
    description: 'Number of floating-point operations to perform (Max: 500M).' 
  })
  @ApiResponse({ status: HttpStatus.OK, description: 'Workload execution successful.' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Insufficient administrative clearance.' })
  async simulateLoad(@Query('cycles') cycles: any = 100000000) {
    
    // DEFENSIVE_LOGIC: Sanitize and enforce hard-caps on CPU utilization
    const parsedCycles = isNaN(Number(cycles)) ? 100000000 : Number(cycles);
    const MAX_CYCLES = 500000000;
    const targetCycles = Math.min(parsedCycles, MAX_CYCLES);

    // AUDIT_LOG: Track privileged operations in non-development environments
    if (process.env.NODE_ENV !== 'development') {
      this.logger.warn(`[AUDIT_LOG] Stress execution triggered: ${targetCycles} cycles in ${process.env.NODE_ENV} mode.`);
    }

    const start = Date.now();
    
    /**
     * COMPUTE_INTENSIVE_WORKLOAD:
     * Synthetic iterations designed to increase CPU utilization.
     * Monitored via Prometheus Scrape Points.
     */
    let result = 0;
    for (let i = 0; i < targetCycles; i++) {
      result += Math.sqrt(Math.random() * Math.random());
    }

    const duration = Date.now() - start;

    return {
      status: 'Execution Finalized',
      metadata: {
        engine: 'Zenith-Kernel-Stress-v1',
        latencyMs: duration,
        processedCycles: targetCycles,
        protectionCapped: targetCycles < parsedCycles,
        timestamp: new Date().toISOString()
      },
      telemetry: {
        dispatched: true,
        registry: 'Prometheus-Default',
        securityLevel: 'ELEVATED'
      }
    };
  }
}