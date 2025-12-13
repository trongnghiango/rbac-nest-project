#!/bin/bash

# ============================================
# REFACTOR: USE DI TOKENS INSTEAD OF STRINGS
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🛠️ REFACTORING DI TOKENS (REMOVING MAGIC STRINGS)..."

# ============================================
# 1. UPDATE PORT (DEFINE TOKEN CONSTANT)
# ============================================
# Định nghĩa LOGGER_TOKEN ngay cạnh Interface ILogger
cat > src/core/shared/application/ports/logger.port.ts << 'EOF'
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export interface LogContext {
  requestId?: string;
  userId?: number | string;
  ipAddress?: string;
  method?: string;
  url?: string;
  [key: string]: any;
}

// ✅ PRO WAY: Định nghĩa Token ở đây
export const LOGGER_TOKEN = 'ILogger';

export interface ILogger {
  debug(message: string, context?: LogContext): void;
  info(message: string, context?: LogContext): void;
  warn(message: string, context?: LogContext): void;
  error(message: string, error?: Error, context?: LogContext): void;

  withContext(context: LogContext): ILogger;
  createChildLogger(module: string): ILogger;
}
EOF

# ============================================
# 2. UPDATE MODULE (USE TOKEN IN PROVIDERS)
# ============================================
cat > src/modules/logging/logging.module.ts << 'EOF'
import { Module, DynamicModule, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WinstonFactory } from './infrastructure/winston/winston.factory';
import { WinstonLoggerAdapter } from './infrastructure/winston/winston-logger.adapter';
// Import Token
import { LOGGER_TOKEN } from '../../core/shared/application/ports/logger.port';

@Global()
@Module({})
export class LoggingModule {
  static forRootAsync(): DynamicModule {
    return {
      module: LoggingModule,
      imports: [ConfigModule],
      providers: [
        WinstonFactory,
        {
          provide: 'WINSTON_LOGGER', // Cái này nội bộ module, để string cũng tạm được
          useFactory: (factory: WinstonFactory) => factory.createLogger(),
          inject: [WinstonFactory],
        },
        {
          provide: LOGGER_TOKEN, // ✅ Dùng Token Constant
          useClass: WinstonLoggerAdapter,
        },
      ],
      exports: [LOGGER_TOKEN], // ✅ Export bằng Token
    };
  }
}
EOF

# ============================================
# 3. UPDATE MIDDLEWARE (USE TOKEN IN INJECT)
# ============================================
cat > src/api/middleware/request-logging.middleware.ts << 'EOF'
import { Injectable, NestMiddleware, Inject } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import type { ILogger } from '../../core/shared/application/ports/logger.port';
// Import Token
import { LOGGER_TOKEN } from '../../core/shared/application/ports/logger.port';

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  // ✅ Dùng Token Constant trong @Inject
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    let rawRequestId = req.headers['x-request-id'];
    if (Array.isArray(rawRequestId)) {
      rawRequestId = rawRequestId[0];
    }
    const requestId = rawRequestId || `req-${Date.now()}`;

    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);

    this.logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
      requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const statusCode = res.statusCode;

      const message = `Request Completed: ${statusCode} (${duration}ms)`;
      const context = {
        requestId,
        statusCode,
        duration,
      };

      if (statusCode >= 500) {
        this.logger.error(message, undefined, context);
      } else if (statusCode >= 400) {
        this.logger.warn(message, context);
      } else {
        this.logger.info(message, context);
      }
    });

    next();
  }
}
EOF

success "✅ REFACTORED TO USE CONSTANT TOKENS!"
echo "👉 App is now using LOGGER_TOKEN instead of 'ILogger' string."