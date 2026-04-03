import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Zenith-Bootstrap');
  const app = await NestFactory.create(AppModule);

  /**
   * SECURITY LAYER: HELMET (Advanced Configuration)
   */
  app.use(helmet({
    hidePoweredBy: true,
    hsts: process.env.NODE_ENV === 'production',
  }));

  /**
   * INFORMATION EXPOSURE: Remove X-Powered-By & Etag
   */
  const expressApp = app.getHttpAdapter().getInstance();
  expressApp.disable('x-powered-by');
  expressApp.disable('etag');

  /**
   * GLOBAL API CONFIGURATION
   */
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  /**
   * SWAGGER UI CONFIGURATION (Documentation Layer)
   * PATH: http://localhost:3000/docs
   */
  const config = new DocumentBuilder()
    .setTitle('Zenith Project API')
    .setDescription('The official secure API documentation for Zenith distributed systems.')
    .setVersion('1.0')
    .addBearerAuth(
      { 
        type: 'http', 
        scheme: 'bearer', 
        bearerFormat: 'JWT', 
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header' 
      },
      'JWT-auth',
    )
    .addTag('Auth', 'User authentication and authorization operations')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  
  // We use '/docs' to keep it separate from the versioned API paths
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  /**
   * GLOBAL VALIDATION PIPE
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
   * SECURE CORS CONFIGURATION
   */
  app.enableCors({
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.ALLOWED_ORIGINS?.split(',') 
      : true, 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization',
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 Zenith Secure API [v1] is operational`);
  logger.log(`📖 Swagger Documentation available at: http://localhost:${port}/docs`);
}

bootstrap();