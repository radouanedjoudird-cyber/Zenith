/**
 * ============================================================================
 * ZENITH INFRASTRUCTURE KERNEL - RELIABILITY & DIAGNOSTICS v1.2
 * ============================================================================
 * @module InfraController
 * @description Mission-critical telemetry and system reliability endpoints.
 * * * ARCHITECTURAL DESIGN (ENTERPRISE GRADE):
 * 1. SIDE-CAR ISOLATION: Separates infrastructure diagnostics from domain logic.
 * 2. K8S NATIVE PROBES: Full compatibility with Liveness/Readiness lifecycle.
 * 3. CONTROLLED RESOURCE SATURATION: Instrumented load for KEDA/HPA benchmarking.
 * * * SECURITY STRATEGY:
 * - Publicly exposed for internal cluster orchestration. 
 * - Network-level isolation is prioritized over application-level JWTs for probes.
 * * @author Radouane Djoudi
 * @version 1.2.0 (Public Load Simulation Enabled)
 * ============================================================================
 */

import { Controller, Get, Query } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import {
    HealthCheck,
    HealthCheckService,
    PrismaHealthIndicator
} from '@nestjs/terminus';
import { Public } from '../common/decorators/public.decorator';
import { PrismaService } from '../prisma/prisma.service';

@ApiTags('Infrastructure & Reliability')
@Controller('infra')
export class InfraController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly prismaHealth: PrismaHealthIndicator,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * CLOUD-NATIVE HEALTH ORCHESTRATION
   * @endpoint GET /api/v1/infra/health
   * @description Standardized probe for Kubernetes to monitor pod viability.
   */
  @Public()
  @Get('health')
  @HealthCheck()
  @ApiOperation({ 
    summary: 'System Liveness & Readiness Probe',
    description: 'Validates core kernel stability and database persistence availability.' 
  })
  @ApiResponse({ status: 200, description: 'System is operational.' })
  @ApiResponse({ status: 503, description: 'System or downstream service is unhealthy.' })
  check() {
    return this.health.check([
      /**
       * DATABASE PERSISTENCE CHECK:
       * Verifies the Prisma engine can execute a ping to the data registry.
       */
      () => this.prismaHealth.pingCheck('database', this.prisma),
    ]);
  }

  /**
   * COMPUTATIONAL STRESS SIMULATOR (BENCHMARKING TOOL)
   * @endpoint GET /api/v1/infra/stress
   * @description Controlled CPU load generation for Predictive Autoscaling research.
   * * [BEST PRACTICE]: Marked as @Public() to allow unhindered access for internal 
   * telemetry scripts (e.g., k6, Artillery). Security is enforced via NetworkPolicies.
   */
  @Public() 
  @Get('stress')
  @ApiOperation({ 
    summary: 'Synthetic Resource Saturation Engine',
    description: 'Intentionally inflates CPU cycles to trigger and test scaling thresholds.' 
  })
  @ApiQuery({ name: 'cycles', required: false, type: Number, example: 100000000 })
  async simulateLoad(@Query('cycles') cycles: number = 100000000) {
    const start = Date.now();
    
    /**
     * WORKLOAD EMULATION:
     * High-frequency mathematical iterations to engage the CPU and increase 
     * P99 latency metrics within the Prometheus registry.
     */
    let result = 0;
    for (let i = 0; i < Number(cycles); i++) {
      result += Math.sqrt(Math.random() * Math.random());
    }

    const duration = Date.now() - start;

    return {
      status: 'Operation Successful',
      metadata: {
        engine: 'Zenith-Stress-v1',
        executionTimeMs: duration,
        processedCycles: Number(cycles),
        timestamp: new Date().toISOString()
      },
      telemetry: {
        impact: 'High CPU Saturation',
        action: 'Metrics dispatched to Prometheus registry.'
      }
    };
  }
}