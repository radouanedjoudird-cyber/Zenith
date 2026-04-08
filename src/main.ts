import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { WinstonModule } from 'nest-winston';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { winstonConfig } from './common/logger/winston.config';

async function bootstrap() {
  // BOOTSTRAP: Using Winston as the primary logger for the entire kernel
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
  });

  const logger = new Logger('Zenith-Bootstrap');

  // SECURITY: Hardening the HTTP headers
  app.use(helmet());

  // STRUCTURE: API Versioning & Global Prefix
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // FILTERS: Standardizing all system responses
  app.useGlobalFilters(new HttpExceptionFilter());

  // VALIDATION: Strict payload enforcement (Zero-Waste Data Policy)
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    disableErrorMessages: process.env.NODE_ENV === 'production',
  }));

  // SWAGGER: Interactive API Documentation
  const config = new DocumentBuilder()
    .setTitle('Zenith Secure API')
    .setVersion('1.0')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'JWT-auth')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  
  logger.log(`🚀 Zenith Secure Engine started on port ${port}`);
}
bootstrap();