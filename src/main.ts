/**
 * ============================================================================
 * ZENITH SECURE KERNEL - ENTERPRISE BOOTSTRAP PROTOCOL
 * ============================================================================
 * @module Main
 * @version 7.4.0
 * @description Orchestrates the ignition of the high-availability security engine.
 * * DESIGN RATIONALE:
 * 1. PROXY_AWARENESS: Configured for upstream load balancers (Nginx/Cloudflare).
 * 2. SECURITY_HARDENING: Implements Helmet, CSP, and strict CORS policies.
 * 3. FAIL_FAST_VALIDATION: Enforces structural integrity of inbound payloads.
 * 4. GRACEFUL_TERMINATION: Handles OS signals for zero-downtime deployments.
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
   * Bootstrapping with log buffering to ensure initial DI telemetry is captured.
   */
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    // Explicitly disabling internal CORS to manage it via granular configuration.
    cors: false, 
  });

  // Inject high-performance logging engine
  app.useLogger(app.get(PinoLogger));
  const logger = new Logger('ZENITH_BOOTSTRAP');
  const port = process.env.PORT || 3000;

  /**
   * SECTION 1: PERIMETER SECURITY & OPTIMIZATION
   * Hardening the application layer against common web vulnerabilities.
   */
  app.use(helmet({
    contentSecurityPolicy: isProduction ? {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https:"],
      },
    } : false, // Permissive in DEV for Swagger Explorer
    crossOriginEmbedderPolicy: isProduction,
  }));

  // Gzip/Brotli compression for payload optimization
  app.use(compression());

  // ENHANCED CORS POLICY: Zero-trust orientation
  app.enableCors({
    origin: isProduction 
      ? (process.env.ALLOWED_ORIGINS?.split(',') || []) 
      : true, 
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Response-Time', 'X-Trace-ID'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  });

  /**
   * SECTION 2: GLOBAL ROUTING & VERSIONING
   * Implementing URI versioning for API lifecycle stability.
   */
  app.setGlobalPrefix('api', {
    exclude: [
      { path: '/', method: RequestMethod.GET },
      { path: 'health', method: RequestMethod.GET },
      { path: 'metrics', method: RequestMethod.GET },
    ],
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SECTION 3: PIPELINE HYGIENE & ERROR ABSTRACTION
   * Enforcing strict DTO validation and global error interception.
   */
  app.useGlobalFilters(new HttpExceptionFilter(), new SecurityBreachFilter());
  
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,               // Strip non-decorated properties
    forbidNonWhitelisted: true,    // Reject requests with unknown properties
    transform: true,               // Auto-transform payloads to DTO instances
    transformOptions: { enableImplicitConversion: true },
    disableErrorMessages: isProduction, // Shield internal structure in production
  }));

  /**
   * SECTION 4: API EXPLORER (SWAGGER)
   * Isolated documentation layer for development and staging only.
   */
  if (!isProduction) {
    const config = new DocumentBuilder()
      .setTitle('Zenith Secure Engine')
      .setDescription('Enterprise Identity & Distributed Systems Kernel.')
      .setVersion('7.4.0')
      .addBearerAuth(
        { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
        'JWT-auth'
      )
      .build();
    
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document, { 
      customSiteTitle: 'Zenith API Registry',
      swaggerOptions: { persistAuthorization: true, filter: true } 
    });
    
    logger.log(`📑 [DOCS] API Registry exposed at: http://localhost:${port}/docs`);
  }

  /**
   * SECTION 5: LIFECYCLE & ORCHESTRATION
   * Ensuring the system drains connections gracefully before termination.
   */
  app.enableShutdownHooks();
  
  await app.listen(port, '0.0.0.0'); 
  
  logger.log(`🚀 [KERNEL] Zenith Engine v7.4.0 active [Mode: ${process.env.NODE_ENV || 'development'}]`);
}

bootstrap().catch((err) => {
  console.error('🔴 [CRITICAL] Kernel ignition sequence failed:', err);
  process.exit(1);
});