/**
 * @fileoverview Zenith Secure Kernel - Enterprise Bootstrap Protocol.
 * Orchestrates the initialization of the high-availability security engine.
 * Implements Zero-Trust ingress, hardware-bound telemetry, and forensic auditing.
 * * @package Zenith-Core
 * @version 6.0.0
 * @author Radouane Djoudi
 * @license Restricted - Enterprise Architecture
 */

import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { WinstonModule } from 'nest-winston';
import { AppModule } from './app.module';

/* --- SECURITY SHIELD INTEGRATION --- */
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { SecurityBreachFilter } from './common/filters/security-breach.filter';
import { winstonConfig } from './common/logger/winston.config';

/**
 * Boots the Zenith Secure Engine.
 * Configures the execution environment, security perimeter, and API contracts.
 * * @async
 * @function bootstrap
 * @returns {Promise<void>}
 */
async function bootstrap(): Promise<void> {
  /**
   * INITIALIZATION:
   * Booting with Winston as the primary telemetry provider for forensic traceability.
   */
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    cors: false, // Managed via strict whitelist in the networking section.
  });

  const logger = new Logger('ZENITH_BOOTSTRAP');
  const port = process.env.PORT || 3000;

  /**
   * SECTION 1: NETWORK & SECURITY HEADERS
   * Implements Helmet for CSP, HSTS, and protection against sniffing attacks.
   */
  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
  }));

  /**
   * SECTION 2: THROUGHPUT OPTIMIZATION
   * Compresses payloads to maximize bandwidth efficiency in distributed nodes.
   */
  app.use(compression());

  /**
   * SECTION 3: CORS - RESOURCE ISOLATION
   * Enforces strict origin control to prevent CSRF and cross-domain identity theft.
   */
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:5173',
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Session-ID', 'X-Trace-ID'], 
  });

  /**
   * SECTION 4: ARCHITECTURAL STRUCTURE
   * Implements Global Prefixing and Semantic Versioning (SemVer).
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SECTION 5: FAULT TOLERANCE & SECURITY INTERCEPTION
   * 🛡️ Multi-layered Defense:
   * 1. HttpExceptionFilter: Catch-all for unified error responses.
   * 2. SecurityBreachFilter: Specialized radar for device-identity anomalies.
   */
  app.useGlobalFilters(
    new HttpExceptionFilter(),    
    new SecurityBreachFilter(),   
  );

  /**
   * SECTION 6: DATA INTEGRITY & VALIDATION
   * Enforces strict DTO contracts and prevents mass-assignment vulnerabilities.
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
   * SECTION 7: API BLUEPRINT (SWAGGER)
   * Exposes system capabilities for Permission-Based Access Control (PBAC).
   */
  const config = new DocumentBuilder()
    .setTitle('Zenith Secure Engine | Registry')
    .setDescription(
      'Enterprise IAM Kernel with Hardware-Bound Session Guarding.\n\n' +
      '**Infrastructure:** Node.js NestJS v10 | MongoDB | Prisma.',
    )
    .setVersion('6.0.0')
    .setContact('Radouane Djoudi', 'https://github.com/radouanedjoudi', 'admin@zenith-systems.dz')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT',
        name: 'Authorization',
        in: 'header'
      }, 
      'JWT-auth' 
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, 
      displayRequestDuration: true, 
    },
    customSiteTitle: 'Zenith API Docs | Security Intelligence',
  });

  /**
   * SECTION 8: LIFECYCLE MANAGEMENT
   * Ensures graceful termination of database pools and background processes.
   */
  app.enableShutdownHooks();

  /**
   * KERNEL IGNITION
   */
  await app.listen(port);
  
  logger.log(`🚀 [KERNEL] Zenith Engine v6.0 operational on port: ${port}`);
  logger.log(`🛡️ [INFRA] Hardware Fingerprinting and Forensic Shield active.`);
}

/**
 * GLOBAL PANIC HANDLER:
 * Captures catastrophic failures during the boot sequence.
 */
bootstrap().catch((err) => {
  const panicLogger = new Logger('ZENITH_PANIC');
  panicLogger.error('❌ CRITICAL: Kernel ignition failed', err.stack);
  process.exit(1);
});