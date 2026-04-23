import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import * as fs from 'fs';
import * as dns from 'dns';

async function bootstrap() {
  // [FIX 1]: Ép Node.js luôn dùng IPv4 thay vì IPv6 để kết nối đến API Telegram ổn định 100%
  dns.setDefaultResultOrder('ipv4first');

  const uploadDir = 'uploads/dental/converted';
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const app = await NestFactory.create(AppModule, { bufferLogs: true });

  // [FIX 2]: Bật cơ chế Graceful Shutdown. 
  // Khi bạn nhấn Ctrl+C, NestJS sẽ báo cho Telegraf ngắt kết nối Long Polling sạch sẽ trước khi tắt app.
  app.enableShutdownHooks();

  const config = app.get(ConfigService);
  const logger = app.get(LOGGER_TOKEN);
  app.useLogger(logger);

  const prefix: string = config.get('app.apiPrefix', 'api');
  app.setGlobalPrefix(prefix);

  app.enableCors({
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  const swaggerConfig = new DocumentBuilder()
    .setTitle('ERP/HRM System API')
    .setDescription('The ERP/HRM System API description')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: { persistAuthorization: true },
  });

  const port: number = config.get('app.port', 8080);
  await app.listen(port);

  logger.info(`🚀 API is running on: http://localhost:${port}/${prefix}`, {
    context: 'Bootstrap',
  });
  logger.info(`📂 Static Files on:   http://localhost:${port}/models`, {
    context: 'Bootstrap',
  });
}

bootstrap().catch((err) => console.error('Err::', err['message']));
