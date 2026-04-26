/**
 * ============================================================================
 * ZENITH SECURE KERNEL - INFRASTRUCTURE & RELIABILITY MODULE
 * ============================================================================
 * @module InfraController
 * @description Mission-critical telemetry, diagnostics, and system probes.
 * * ARCHITECTURAL COMPLIANCE:
 * 1. RBAC_ENFORCEMENT: Stress-testing vectors are gated via Role-Based Access Control.
 * 2. CLOUD_NATIVE_READY: Implements Liveness/Readiness patterns for K8s/Docker.
 * 3. SATURATION_LIMITER: Hard-capped execution cycles to prevent resource exhaustion.
 * ============================================================================
 */

import {
  Controller,
  Get,
  Logger,
  Query,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { HealthCheck, HealthCheckService, PrismaHealthIndicator } from '@nestjs/terminus';

/* --- SECURITY SCHEMAS (Corrected Paths Based on Project Tree) --- */
import { AtGuard } from '../auth/guards/at.guard'; // Corrected: Using AtGuard instead of JwtAuthGuard
import { Public } from '../common/decorators/public.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';
import { RolesGuard } from '../common/guards/roles.guard'; // Corrected: RolesGuard is in common/guards

/* --- INSTRUMENTATION & SERVICES --- */
import { MonitoringInterceptor } from '../common/interceptors/monitoring.interceptor';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('Infrastructure & Reliability')
@Controller('infra')
@UseInterceptors(MonitoringInterceptor)
export class InfraController {
  private readonly logger = new Logger('ZENITH_INFRA_ENGINE');

  constructor(
    private readonly health: HealthCheckService,
    private readonly prismaHealth: PrismaHealthIndicator,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * @endpoint GET /api/v1/infra/health
   * @access Public (Whitelisted for Orchestrator Probes)
   * @description Standardized health check for Kubernetes liveness/readiness probes.
   */
  @Public()
  @Get('health')
  @HealthCheck()
  @ApiOperation({ 
    summary: 'System Liveness Probe',
    description: 'Critical check for database persistence and kernel stability.' 
  })
  @ApiResponse({ status: 200, description: 'Core services operational.' })
  @ApiResponse({ status: 503, description: 'Service degradation detected.' })
  async check() {
    return this.health.check([
      /**
       * PERSISTENCE_LAYER_VALIDATION:
       * Ensures the Prisma ORM maintains a healthy heartbeat with the registry.
       */
      () => this.prismaHealth.pingCheck('database', this.prisma),
    ]);
  }

  /**
   * @endpoint GET /api/v1/infra/stress
   * @access Restricted (Admin Only)
   * @description Generates controlled CPU saturation for autoscaling verification.
   */
  @Get('stress')
  @UseGuards(AtGuard, RolesGuard) // Changed to AtGuard as per your project structure
  @Roles(Role.ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Resource Saturation Simulation',
    description: 'Authorized stress testing for benchmarking P99 latency and scaling triggers.' 
  })
  @ApiQuery({ name: 'cycles', type: Number, required: false, example: 100000000 })
  @ApiResponse({ status: 200, description: 'Workload execution successful.' })
  @ApiResponse({ status: 403, description: 'Privileged access required.' })
  async simulateLoad(@Query('cycles') cycles: any = 100000000) {
    
    /**
     * DEFENSIVE_PROGRAMMING:
     * Enforce a hard cap (MAX_CYCLES) to prevent unintentional self-inflicted DoS.
     */
    const parsedCycles = isNaN(Number(cycles)) ? 100000000 : Number(cycles);
    const MAX_CYCLES = 500000000;
    const targetCycles = Math.min(parsedCycles, MAX_CYCLES);

    if (process.env.NODE_ENV === 'production') {
      this.logger.warn(`[AUDIT_LOG] Stress execution triggered by Admin in PRODUCTION environment.`);
    }

    const start = Date.now();
    
    /**
     * COMPUTE_INTENSIVE_WORKLOAD:
     * Synthetic iterations designed to increase CPU utilization, 
     * reflected in Prometheus through the MonitoringInterceptor.
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
        registry: 'Prometheus-Default'
      }
    };
  }
}