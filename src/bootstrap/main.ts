import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

async function bootstrap() {
  // 1. Bật bufferLogs: true để NestJS giữ log lại, không in ra console bằng logger mặc định
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const config = app.get(ConfigService);

  // 2. Lấy Winston Logger từ Container
  const logger = app.get(LOGGER_TOKEN);

  // 3. Gán Winston làm Logger chính cho toàn bộ hệ thống NestJS
  app.useLogger(logger);

  // 4. (Tùy chọn) Flush logs đã buffer (nếu có log nào xảy ra trong quá trình khởi tạo)
  // app.flushLogs();

  const prefix: string = config.get('app.apiPrefix', 'api');
  app.setGlobalPrefix(prefix);

  app.enableCors();

  // --- SWAGGER CONFIGURATION ---
  const swaggerConfig = new DocumentBuilder()
    .setTitle('RBAC System API')
    .setDescription('The RBAC System API description')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });
  // -----------------------------

  const port: number = config.get('app.port', 3000);
  await app.listen(port);

  // Dùng logger xịn để log dòng khởi động
  logger.info(`🚀 API is running on: http://localhost:${port}/${prefix}`, { context: 'Bootstrap' });
  logger.info(`📚 Swagger Docs:      http://localhost:${port}/docs`, { context: 'Bootstrap' });
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
bootstrap().catch((err) => console.error('Err::', err['message']));
