#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🎙️ REPLACING DEFAULT NESTJS LOGGER WITH WINSTON..."

# 1. Nâng cấp Adapter để tương thích cả NestJS Core và Application Code
# NestJS truyền: log(message, contextString)
# App ta dùng: info(message, contextObj)
cat > src/modules/logging/infrastructure/winston/winston-logger.adapter.ts << 'EOF'
import { Injectable, Inject, LoggerService } from '@nestjs/common';
import * as winston from 'winston';
import {
  ILogger,
  LogContext,
} from '@core/shared/application/ports/logger.port';
import { RequestContextService } from '@core/shared/infrastructure/context/request-context.service';

@Injectable()
export class WinstonLoggerAdapter implements ILogger, LoggerService {
  private context: LogContext = {};

  constructor(
    @Inject('WINSTON_LOGGER') private readonly winstonLogger: winston.Logger,
  ) {}

  private getTraceInfo() {
    return {
      requestId: RequestContextService.getRequestId(),
    };
  }

  // --- Helper để chuẩn hóa tham số từ NestJS Core ---
  private normalizeParams(message: any, ...optionalParams: any[]) {
    let contextObj: LogContext = {};

    // Xử lý trường hợp NestJS gửi context là string ở tham số cuối
    if (optionalParams.length > 0) {
      const lastParam = optionalParams[optionalParams.length - 1];
      if (typeof lastParam === 'string') {
        contextObj.context = lastParam; // Gán vào field context
        // Bỏ string context ra khỏi params để không bị trùng
        // optionalParams.pop();
      } else if (typeof lastParam === 'object') {
        contextObj = { ...lastParam };
      }
    }

    // Nếu message là object (NestJS hay log object), stringify nó hoặc gán vào meta
    const msgStr = typeof message === 'string' ? message : JSON.stringify(message);

    return { msgStr, contextObj };
  }

  // --- Implementation cho LoggerService (NestJS Core gọi cái này) ---

  log(message: any, ...optionalParams: any[]) {
    // Map 'log' của Nest sang 'info' của Winston
    this.info(message, ...optionalParams);
  }

  // --- Implementation cho ILogger (App của ta gọi cái này) ---

  debug(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(message, ...optionalParams);
    this.callWinston('debug', msgStr, contextObj);
  }

  info(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(message, ...optionalParams);
    this.callWinston('info', msgStr, contextObj);
  }

  warn(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(message, ...optionalParams);
    this.callWinston('warn', msgStr, contextObj);
  }

  error(message: any, ...optionalParams: any[]): void {
    // NestJS thường gửi stack trace ở tham số thứ 2 hoặc 3
    const { msgStr, contextObj } = this.normalizeParams(message, ...optionalParams);

    // Tìm Error object nếu có trong params
    const errorObj = optionalParams.find(p => p instanceof Error);
    const meta = { ...contextObj };

    if (errorObj) {
        meta.stack = errorObj.stack;
        meta.error = errorObj.message;
    }

    this.callWinston('error', msgStr, meta);
  }

  // --- Context Methods ---

  withContext(context: LogContext): ILogger {
    const child = new WinstonLoggerAdapter(this.winstonLogger);
    child.context = { ...this.context, ...context };
    return child;
  }

  createChildLogger(module: string): ILogger {
    return this.withContext({ context: module }); // Map 'label' hoặc 'context' tùy config winston
  }

  private callWinston(level: string, message: string, context?: LogContext): void {
    this.winstonLogger.log(level, message, {
      ...this.context,
      ...this.getTraceInfo(),
      ...context,
    });
  }
}
EOF

# 2. Cập nhật main.ts để sử dụng custom logger
log "⚙️ UPDATING MAIN.TS TO USE BUFFER LOGS..."

cat > src/bootstrap/main.ts << 'EOF'
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
EOF

success "✅ LOGGER REPLACED! NestJS system logs will now use Winston."
echo "👉 Restart server: npm run start:dev"
echo "👉 You should see logs in JSON format (including 'InstanceLoader', 'RoutesResolver', etc.)"