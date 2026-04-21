/**
 * ============================================================================
 * ZENITH SECURE KERNEL - ENTERPRISE BOOTSTRAP PROTOCOL
 * ============================================================================
 * @module Main
 * @description Orchestrates the ignition of the high-availability security engine.
 * * ARCHITECTURAL DESIGN (BIG-TECH STANDARDS):
 * 1. RESILIENCE: Graceful shutdown hooks for Zero-Downtime deployments in K8s.
 * 2. SECURITY: Hardened Helmet configuration and strict CORS resource isolation.
 * 3. VALIDATION: Fail-fast validation strategy to optimize CPU cycles for scaling.
 * 4. TRACEABILITY: Integrated Winston logger for forensic system audits.
 * * @author Radouane Djoudi
 * @version 7.0.0
 * ============================================================================
 */

import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { WinstonModule } from 'nest-winston';
import { AppModule } from './app.module';

/* --- INFRASTRUCTURE INTEGRATION --- */
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { SecurityBreachFilter } from './common/filters/security-breach.filter';
import { winstonConfig } from './common/logger/winston.config';

async function bootstrap(): Promise<void> {
  /**
   * INITIALIZATION:
   * Booting with Winston for high-fidelity traceability.
   * Internal Nest logger is replaced by Winston to ensure centralized log formatting.
   */
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    cors: false, // Managed explicitly below
  });

  const logger = new Logger('ZENITH_BOOTSTRAP');
  const port = process.env.PORT || 3000;

  /**
   * SECTION 1: SECURITY PERIMETER (HELMET)
   * Enforces strict HTTP headers to mitigate XSS, Clickjacking, and Sniffing.
   * Strategy: Standardize security posture across all pods.
   */
  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    crossOriginEmbedderPolicy: true,
  }));

  /**
   * SECTION 2: THROUGHPUT OPTIMIZATION
   * Compresses HTTP payloads to maximize bandwidth efficiency. 
   * Vital for 'Scaling' experiments (RQ2) to reduce network I/O latency.
   */
  app.use(compression());

  /**
   * SECTION 3: CORS - IDENTITY-BASED RESOURCE ISOLATION
   * Prevents unauthorized cross-domain telemetry leakage.
   */
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3000'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Trace-ID', 'X-Tenant-ID'], 
  });

  /**
   * SECTION 4: ARCHITECTURAL VERSIONING (SemVer)
   * URI-based versioning (e.g., /api/v1/...) enables non-breaking rolling updates.
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SECTION 5: GLOBAL EXCEPTION FILTERS
   * Standardizes the system's "Failure Domain".
   * This ensures the telemetry engine receives consistent error signals.
   */
  app.useGlobalFilters(
    new HttpExceptionFilter(),    
    new SecurityBreachFilter(),   
  );

  /**
   * SECTION 6: RESOURCE-EFFICIENT VALIDATION (Fail-Fast)
   * Strategy: Reject malformed payloads early to preserve RAM/CPU for legitimate processing.
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,               
      forbidNonWhitelisted: true,    
      transform: true,               
      transformOptions: { enableImplicitConversion: true },
      disableErrorMessages: process.env.NODE_ENV === 'production',
    }),
  );

  /**
   * SECTION 7: API BLUEPRINT & INFRAISTRY REGISTRY
   */
  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Zenith Secure Engine | System Registry')
      .setDescription(
        'Enterprise IAM & Distributed Systems Kernel.\n\n' +
        '**Status:** Predictive Autoscaling Ready (KEDA/Prometheus Optimized).'
      )
      .setVersion('7.0.0')
      .setContact('Radouane Djoudi', 'https://github.com/radouanedjoudi', 'admin@zenith-systems.dz')
      .addBearerAuth(
        { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', name: 'Authorization', in: 'header' }, 
        'JWT-auth' 
      )
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document, {
      swaggerOptions: { persistAuthorization: true, displayRequestDuration: true },
      customSiteTitle: 'Zenith Docs | Infrastructure Intelligence',
    });
  }

  /**
   * SECTION 8: LIFECYCLE & K8s COMPLIANCE
   * Enables shutdown hooks to allow the pod to drain active requests 
   * during horizontal scale-down events (Autoscaling).
   */
  app.enableShutdownHooks();

  /**
   * KERNEL IGNITION
   */
  await app.listen(port);
  
  logger.log(`\x1b[32m🚀 [KERNEL] Zenith Engine v7.0 operational on port: ${port}\x1b[0m`);
  logger.log(`\x1b[34m🛡️ [INFRA] Predictive Monitoring & Resource Guard active.\x1b[0m`);
}

/**
 * GLOBAL PANIC RECOVERY PROTOCOL
 */
bootstrap().catch((err) => {
  const panicLogger = new Logger('ZENITH_PANIC');
  panicLogger.error('❌ CRITICAL: Kernel ignition failed', err.stack);
  process.exit(1);
});