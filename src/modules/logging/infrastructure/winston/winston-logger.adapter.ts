import { Injectable, Inject, Scope } from '@nestjs/common';
import * as winston from 'winston';
import {
  ILogger,
  LogContext,
} from '../../../../core/shared/application/ports/logger.port';
import { RequestContextService } from '../../../../core/shared/infrastructure/context/request-context.service';

// CHUYỂN VỀ DEFAULT SCOPE (SINGLETON) - TỐT CHO HIỆU NĂNG
@Injectable()
export class WinstonLoggerAdapter implements ILogger {
  private context: LogContext = {};

  constructor(
    @Inject('WINSTON_LOGGER') private readonly winstonLogger: winston.Logger,
  ) {}

  // Hàm này tự động lấy RequestID từ "túi thần kỳ" ALS
  private getTraceInfo() {
    return {
      requestId: RequestContextService.getRequestId(),
      // Có thể lấy thêm userId nếu lưu vào ALS sau bước Auth
    };
  }

  debug(message: string, context?: LogContext): void {
    this.log('debug', message, context);
  }

  info(message: string, context?: LogContext): void {
    this.log('info', message, context);
  }

  warn(message: string, context?: LogContext): void {
    this.log('warn', message, context);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    const errorMetadata = error
      ? {
          name: error.name,
          message: error.message,
          stack: error.stack,
        }
      : undefined;

    // Merge error metadata vào context để in ra JSON đẹp
    this.log('error', message, { ...context, ...errorMetadata });
  }

  withContext(context: LogContext): ILogger {
    // Tạo logger con, vẫn giữ bản chất singleton nhưng merge context tĩnh
    const child = new WinstonLoggerAdapter(this.winstonLogger);
    child.context = { ...this.context, ...context };
    return child;
  }

  createChildLogger(module: string): ILogger {
    return this.withContext({ label: module });
  }

  private log(level: string, message: string, context?: LogContext): void {
    // Merge 3 nguồn context:
    // 1. Context tĩnh của class (this.context)
    // 2. Trace Info động từ ALS (requestId)
    // 3. Context truyền vào hàm log

    this.winstonLogger.log(level, message, {
      ...this.context,
      ...this.getTraceInfo(), // Tự động inject RequestID
      ...context,
    });
  }
}
