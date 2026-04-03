import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module'; // IMPORTANT: This line was missing or lowercased

async function bootstrap() {
  const logger = new Logger('Zenith-Bootstrap');
  
  // High Performance: Use the correctly capitalized AppModule
  const app = await NestFactory.create(AppModule);

  /**
   * SECURITY LAYER: HELMET
   * Protection against common web vulnerabilities (XSS, Clickjacking, etc.)
   */
  app.use(helmet({
    hidePoweredBy: true,
    hsts: process.env.NODE_ENV === 'production',
  }));

  /**
   * PERFORMANCE OPTIMIZATION:
   * Disabling headers that reveal the technology stack (Express) and removing ETags to save bandwidth.
   */
  const expressApp = app.getHttpAdapter().getInstance();
  expressApp.disable('x-powered-by');
  expressApp.disable('etag');

  /**
   * GLOBAL API STRUCTURE:
   * Enforcing standard 'api' prefix and URI-based versioning for clean architecture.
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SWAGGER UI CONFIGURATION:
   * Integrated JWT Bearer authentication globally for the interactive documentation.
   */
  const config = new DocumentBuilder()
    .setTitle('Zenith Secure API')
    .setDescription('Enterprise-grade distributed systems API documentation.')
    .setVersion('1.0')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT', 
        name: 'Authorization',
        description: 'Simply paste your JWT access_token below.',
        in: 'header' 
      },
      'JWT-auth', // This KEY must match the @ApiBearerAuth('JWT-auth') in your controllers
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { 
      persistAuthorization: true, // Saves the token even after page refresh (productivity boost)
    },
  });

  /**
   * GLOBAL VALIDATION PIPES:
   * Whitelisting removes unexpected properties from requests instantly, improving security and speed.
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,              
      forbidNonWhitelisted: true,   
      transform: true,              
      disableErrorMessages: process.env.NODE_ENV === 'production',
    }),
  );

  /**
   * SECURE CORS:
   * Allows frontend integration during development and restricted origins in production.
   */
  app.enableCors({ origin: true, credentials: true });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 Zenith Secure Engine started on port ${port}`);
  logger.log(`📖 Documentation: http://localhost:${port}/docs`);
}

bootstrap();