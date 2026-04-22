/**
 * ============================================================================
 * ZENITH SECURE KERNEL - ENTERPRISE BOOTSTRAP PROTOCOL v7.3.0
 * ============================================================================
 * @module Main
 * @description Orchestrates the ignition of the high-availability security engine.
 * * * ARCHITECTURAL DESIGN (BIG-TECH STANDARDS):
 * 1. ZERO-WARNING ROUTING: Explicit path mapping using named parameters for path-to-regexp v8.
 * 2. HIGH-PERFORMANCE LOGGING: Pino JSON streams for low-latency observability.
 * 3. K8S DRAIN PROTOCOL: Advanced Graceful Shutdown for predictive scaling stability.
 * 4. FAIL-FAST VALIDATION: Synchronous input sanitization to preserve CPU cycles.
 * * @author Radouane Djoudi
 * @version 7.3.0 (Zero-Warning / Production-Ready)
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
  /**
   * INITIALIZATION:
   * Booting with Pino for high-velocity structured logging. 
   * BufferLogs ensures early startup logs aren't lost before Pino is ready.
   */
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true, 
    cors: false, 
  });

  app.useLogger(app.get(PinoLogger));
  const logger = new Logger('ZENITH_BOOTSTRAP');
  const port = process.env.PORT || 3000;

  /**
   * SECTION 1: SECURITY & THROUGHPUT
   * Helmet secures headers; Compression optimizes payload delivery.
   */
  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    crossOriginEmbedderPolicy: true,
  }));
  app.use(compression());

  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Trace-ID'], 
  });

  /**
   * SECTION 2: MODERN ROUTING
   * [FIX]: Explicit exclusion of root and named parameters to satisfy path-to-regexp v8.
   */
  app.setGlobalPrefix('api', {
    exclude: [{ path: '/', method: RequestMethod.GET }], 
  });

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  app.useGlobalFilters(new HttpExceptionFilter(), new SecurityBreachFilter());
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,               
    forbidNonWhitelisted: true,    
    transform: true,               
    transformOptions: { enableImplicitConversion: true },
    disableErrorMessages: process.env.NODE_ENV === 'production',
  }));

  /**
   * SECTION 3: DOCUMENTATION
   */
  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Zenith Secure Engine | System Registry')
      .setDescription('Enterprise IAM & Distributed Systems Kernel.')
      .setVersion('7.3.0')
      .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'JWT-auth')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document, { customSiteTitle: 'Zenith Docs' });
  }

  app.enableShutdownHooks();
  await app.listen(port);
  logger.log(`🚀 [KERNEL] Zenith Engine v7.3.0 operational on port: ${port}`);
}

bootstrap().catch((err) => {
  new Logger('ZENITH_PANIC').error('❌ CRITICAL: Kernel failed', err.stack);
  process.exit(1);
});