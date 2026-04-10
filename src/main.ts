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
 * ARCHITECTURE: High-Availability & Shielded Infrastructure.
 * SECURITY: Zero-Trust Ingress & Defensive Header Orchestration.
 * PERFORMANCE: Optimized for HP-ProBook (Gzip + Winston Caching).
 * * @author Radouane Djoudi
 * @environment Production/Staging (Linux-Standard)
 */
async function bootstrap() {
  // KERNEL INITIALIZATION: Booting with persistent logging.
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
    cors: false, // Explicitly managed below.
  });

  const logger = new Logger('Zenith-Bootstrap');

  // 1. SECURITY: DEFENSIVE HEADERS (HELMET)
  app.use(helmet());

  // 2. NETWORK: THROUGHPUT OPTIMIZATION
  app.use(compression());

  // 3. SECURITY: CROSS-ORIGIN RESOURCE SHARING (CORS)
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    exposedHeaders: ['Authorization'],
  });

  // 4. STRUCTURE: GLOBAL URI PREFIX & VERSIONING
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // 5. EXCEPTION HANDLING: GLOBAL SHIELD
  app.useGlobalFilters(new HttpExceptionFilter());

  // 6. VALIDATION: STRICT PAYLOAD ENFORCEMENT
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,              
    forbidNonWhitelisted: true,   
    transform: true,              
    // PERFORMANCE: Typed validation logic for faster processing.
    transformOptions: { enableImplicitConversion: true },
    disableErrorMessages: process.env.NODE_ENV === 'production',
  }));

  // 7. SWAGGER: ENTERPRISE BLUEPRINT (PBAC READY)
  const config = new DocumentBuilder()
    .setTitle('Zenith')
    .setVersion('2.8.0')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Provide a valid JWT Access Token to access PBAC protected resources.',
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

  // 8. KERNEL DEPLOYMENT
  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 [KERNEL] Zenith Engine operational on port: ${port}`);
  logger.log(`🛡️ [INFRA] Security perimeter active (Zero-Trust enabled).`);
  logger.log(`📖 [DOCS] Blueprint active: http://localhost:${port}/docs`);
}

// CRITICAL PANIC HANDLER
bootstrap().catch((err) => {
  const logger = new Logger('Zenith-Panic');
  logger.error('❌ CRITICAL: Zenith Kernel ignition failure', err.stack);
  process.exit(1);
});