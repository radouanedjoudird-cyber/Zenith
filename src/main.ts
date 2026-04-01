import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Zenith-Bootstrap');
  const app = await NestFactory.create(AppModule);

  /**
   * SECURITY LAYER: HELMET (Advanced Configuration)
   * Helmet protects against common web vulnerabilities by setting HTTP headers.
   */
  app.use(helmet({
    // Hide 'X-Powered-By' header to prevent attackers from knowing we use Express/Node.js
    hidePoweredBy: true,
    // Ensure the site is only accessed via HTTPS
    hsts: process.env.NODE_ENV === 'production',
  }));

  /**
   * INFORMATION EXPOSURE: Remove X-Powered-By
   * Explicitly disabling this header at the Nest/Express level as a second layer of defense.
   */
  const expressApp = app.getHttpAdapter().getInstance();
  expressApp.disable('x-powered-by');
  expressApp.disable('etag'); // Prevent caching-based fingerprinting

  app.setGlobalPrefix('api');

  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * GLOBAL VALIDATION PIPE (Security Hardened)
   * Prevents "Mass Assignment" and "Injection" attacks.
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,              
      forbidNonWhitelisted: true,   
      transform: true,              
      /**
       * INFO EXPOSURE PROTECTION: 
       * Never show detailed validation errors in production. 
       * Detailed errors can leak internal DTO structures to attackers.
       */
      disableErrorMessages: process.env.NODE_ENV === 'production',
    }),
  );

  /**
   * SECURE CORS CONFIGURATION
   * Limits which domains can talk to our API.
   */
  app.enableCors({
    // In production, NEVER use '*', always specify your frontend domain.
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.ALLOWED_ORIGINS?.split(',') 
      : true, 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization',
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 Zenith Secure API [v1] is operational on port: ${port}`);
}

bootstrap();
