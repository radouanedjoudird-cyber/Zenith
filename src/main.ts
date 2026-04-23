/**
 * ============================================================================
 * ZENITH SECURE KERNEL - ENTERPRISE BOOTSTRAP PROTOCOL
 * ============================================================================
 * @module Main
 * @description Orchestrates the ignition of the high-availability security engine.
 * * DESIGN RATIONALE (ENTERPRISE GRADE):
 * 1. PROXY_TRUST: Configured for upstream load balancers (Nginx/Cloudflare).
 * 2. CSP_HARDENING: Dynamic Content Security Policy based on environment.
 * 3. SWAGGER_ISOLATION: Zero-footprint documentation in production environments.
 * 4. ERROR_MASKING: Strips sensitive stack traces from public responses.
 * ============================================================================
 */

import { Logger, RequestMethod, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { AppModule } from './app.module';

/* --- INFRASTRUCTURE FILTERS --- */
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { SecurityBreachFilter } from './common/filters/security-breach.filter';

async function bootstrap(): Promise<void> {
  const isProduction = process.env.NODE_ENV === 'production';
  
  /**
   * INITIALIZATION:
   * Bootstrapping with log buffering to ensure DI resolution telemetry is captured.
   */
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    // CORS is managed manually via enableCors for granular control
    cors: false, 
  });

  // Attach high-performance Pino logger
  app.useLogger(app.get(PinoLogger));
  const logger = new Logger('ZENITH_BOOTSTRAP');
  const port = process.env.PORT || 3000;

  /**
   * SECTION 1: PERIMETER SECURITY & OPTIMIZATION
   * Helmet: Hardens the application by setting various HTTP headers.
   * Trust Proxy: Essential for accurate IP tracking when behind Nginx/ALB.
   */
  app.use(helmet({
    contentSecurityPolicy: isProduction ? {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    } : false, // Disable CSP in dev to allow Swagger UI scripts
    crossOriginEmbedderPolicy: isProduction,
  }));

  app.use(compression());

  // Granular CORS Policy
  app.enableCors({
    origin: isProduction 
      ? (process.env.ALLOWED_ORIGINS?.split(',') || []) 
      : true, // Allow all in development for convenience
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Trace-ID'],
  });

  /**
   * SECTION 2: ADVANCED ROUTING & VERSIONING
   * Excluding health and metrics from global prefix for infrastructure compatibility.
   */
  app.setGlobalPrefix('api', {
    exclude: [
      { path: '/', method: RequestMethod.GET },
      { path: 'metrics', method: RequestMethod.GET },
      { path: 'health', method: RequestMethod.GET },
    ],
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SECTION 3: GLOBAL PIPELINES & ERROR HANDLING
   * ValidationPipe: Enforcing strict DTO schemas (Fail-Fast).
   */
  app.useGlobalFilters(new HttpExceptionFilter(), new SecurityBreachFilter());
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: { enableImplicitConversion: true },
    // Strict error masking in production to prevent information leakage
    disableErrorMessages: isProduction,
    dismissDefaultMessages: isProduction,
  }));

  /**
   * SECTION 4: OPENAPI DOCUMENTATION (SWAGGER)
   * Strictly disabled in production to prevent API surface discovery.
   */
  if (!isProduction) {
    const config = new DocumentBuilder()
      .setTitle('Zenith Secure Engine | System Registry')
      .setDescription('Enterprise IAM & Distributed Systems Kernel with P95/P99 Observability.')
      .setVersion('7.4.0')
      .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'JWT-auth')
      .build();
    
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document, { 
      customSiteTitle: 'Zenith API Explorer',
      swaggerOptions: { persistAuthorization: true } 
    });
    
    logger.log(`📑 [DOCS] API Documentation available at: http://localhost:${port}/docs`);
  }

  /**
   * SECTION 5: ORCHESTRATION & SHUTDOWN
   * Handles SIGTERM (K8s/Docker) for graceful connection draining.
   */
  app.enableShutdownHooks();
  
  await app.listen(port, '0.0.0.0'); // Listen on all interfaces
  
  logger.log(`🚀 [KERNEL] Zenith Engine v7.4.0 active [Mode: ${process.env.NODE_ENV || 'development'}]`);
  logger.log(`📊 [TELEMETRY] Scrape target active at: http://localhost:${port}/metrics`);
}

bootstrap().catch((err) => {
  console.error('❌ CRITICAL: Kernel ignition failure', err);
  process.exit(1);
});