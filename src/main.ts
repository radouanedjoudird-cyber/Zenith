import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import compression from 'compression';
import helmet from 'helmet';
import { WinstonModule } from 'nest-winston';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { winstonConfig } from './common/logger/winston.config';

/**
 * ZENITH SECURE KERNEL - BOOTSTRAP PROTOCOL v5.0 (Global Orchestration)
 * -----------------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURE: High-Availability & Shielded Infrastructure.
 * * * SECURITY: Zero-Trust Ingress & Multi-Device Session Guard.
 * * * COMPLIANCE: Optimized for Distributed Systems & Forensic Auditing.
 */
async function bootstrap() {
  /**
   * KERNEL INITIALIZATION:
   * Booting with Winston as the primary telemetry provider for forensic logs.
   */
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    cors: false, // Managed manually via enableCors for strict whitelist control.
  });

  const logger = new Logger('ZENITH_BOOTSTRAP');

  /**
   * 1. SECURITY: DEFENSIVE HEADERS (HELMET)
   * Enforces CSP, HSTS, and prevents MIME-type sniffing at the edge.
   */
  app.use(helmet());

  /**
   * 2. NETWORK: THROUGHPUT OPTIMIZATION
   * Compresses response bodies to reduce latency on bandwidth-constrained links.
   */
  app.use(compression());

  /**
   * 3. SECURITY: CROSS-ORIGIN RESOURCE SHARING (CORS)
   * Strict whitelisting of originators to prevent CSRF and Cross-Origin attacks.
   */
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:5173', // Vue/React Default
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    credentials: true,
    exposedHeaders: ['Authorization', 'X-Session-ID'], // Essential for multi-device auditing
  });

  /**
   * 4. STRUCTURE: GLOBAL URI PREFIX & VERSIONING
   * Implementing Semantic Versioning to ensure API contract stability.
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * 5. EXCEPTION HANDLING: GLOBAL SHIELD
   * Formats all unhandled exceptions into sanitized, non-leaky forensic responses.
   */
  app.useGlobalFilters(new HttpExceptionFilter());

  /**
   * 6. VALIDATION: STRICT PAYLOAD ENFORCEMENT
   * - Anti-Mass-Assignment via strict whitelisting.
   * - Memory-efficient conversion for incoming DTOs.
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
   * 7. SWAGGER: ENTERPRISE BLUEPRINT (v5.0)
   * Exposes the security context for PBAC (Permissions Based Access Control).
   */
  const config = new DocumentBuilder()
    .setTitle('Zenith Secure Engine | API')
    .setDescription(
      'Enterprise-grade IAM & Distributed Resource Orchestration Kernel.\n\n' +
      '**Security Protocol:** JWT Refresh Token Rotation (RTR) with Multi-Device Isolation.',
    )
    .setVersion('5.0.0')
    .setContact('Radouane Djoudi', 'https://github.com/radouanedjoudi', 'admin@zenith-systems.dz')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Enter your Access Token (AT) to access protected resources.',
        in: 'header'
      }, 
      'JWT-auth' 
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, 
      filter: true,               
      displayRequestDuration: true, 
      docExpansion: 'none',       
    },
    customSiteTitle: 'Zenith API Docs | Security Portal',
  });

  /**
   * 8. SYSTEM RESILIENCE: GRACEFUL SHUTDOWN
   * Ensures the database and connection pools close properly on SIGTERM.
   */
  app.enableShutdownHooks();

  /**
   * 9. KERNEL DEPLOYMENT
   */
  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 [KERNEL] Zenith Engine operational on port: ${port}`);
  logger.log(`🛡️ [INFRA] Security perimeter active (Zero-Trust enabled).`);
  logger.log(`📖 [DOCS] Blueprint active: http://localhost:${port}/docs`);
}

/**
 * CRITICAL PANIC HANDLER
 */
bootstrap().catch((err) => {
  const logger = new Logger('ZENITH_PANIC');
  logger.error('❌ CRITICAL: Kernel ignition failure', err.stack);
  process.exit(1);
});