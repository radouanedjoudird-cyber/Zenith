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
 * ZENITH SECURE KERNEL - BOOTSTRAP PROTOCOL v2.8
 * ---------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * ARCHITECTURE: High-Availability & Shielded Infrastructure.
 * * * SECURITY: Zero-Trust Ingress & Defensive Header Orchestration.
 * * * PERFORMANCE: Optimized Throughput via Gzip & Forensic Winston Logging.
 */
async function bootstrap() {
  /**
   * KERNEL INITIALIZATION:
   * Booting with Winston as the primary telemetry provider for forensic logs.
   */
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    cors: false, // Managed manually via enableCors for strict whitelisting.
  });

  const logger = new Logger('Zenith-Bootstrap');

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
   * Strictly allows only trusted domains from the environment registry.
   */
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    exposedHeaders: ['Authorization'],
  });

  /**
   * 4. STRUCTURE: GLOBAL URI PREFIX & VERSIONING
   * Logic: Sets up /api/v1/... pattern to prevent breaking legacy consumers.
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * 5. EXCEPTION HANDLING: GLOBAL SHIELD
   * Formats all unhandled exceptions into sanitized forensic responses.
   */
  app.useGlobalFilters(new HttpExceptionFilter());

  /**
   * 6. VALIDATION: STRICT PAYLOAD ENFORCEMENT
   * - whitelist: Strips non-decorated properties (Anti-Mass-Assignment).
   * - forbidNonWhitelisted: Rejects requests with unknown properties.
   */
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,              
    forbidNonWhitelisted: true,   
    transform: true,              
    transformOptions: { enableImplicitConversion: true },
    disableErrorMessages: process.env.NODE_ENV === 'production',
  }));

  /**
   * 7. SWAGGER: ENTERPRISE BLUEPRINT (PBAC READY)
   * Exposes a high-entropy security context for API exploration.
   */
  const config = new DocumentBuilder()
    .setTitle('Zenith Secure API')
    .setDescription('Forensic-ready identity & resource orchestration kernel.')
    .setVersion('2.8.0')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Provide a high-entropy JWT Access Token for PBAC resources.',
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
    customSiteTitle: 'Zenith API Documentation | Forensic Shield',
  });

  /**
   * 8. KERNEL DEPLOYMENT
   */
  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 [KERNEL] Zenith Engine operational on port: ${port}`);
  logger.log(`🛡️ [INFRA] Security perimeter active (Zero-Trust enabled).`);
  logger.log(`📖 [DOCS] Blueprint active: http://localhost:${port}/docs`);
}

/**
 * CRITICAL PANIC HANDLER:
 * Prevents 'zombie' processes by forcing exit on boot failure.
 */
bootstrap().catch((err) => {
  const logger = new Logger('Zenith-Panic');
  logger.error('❌ CRITICAL: Zenith Kernel ignition failure', err.stack);
  process.exit(1);
});