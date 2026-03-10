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
    const msgStr =
      typeof message === 'string' ? message : JSON.stringify(message);

    return { msgStr, contextObj };
  }

  // --- Implementation cho LoggerService (NestJS Core gọi cái này) ---

  log(message: any, ...optionalParams: any[]) {
    // Map 'log' của Nest sang 'info' của Winston
    this.info(message, ...optionalParams);
  }

  // --- Implementation cho ILogger (App của ta gọi cái này) ---

  debug(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('debug', msgStr, contextObj);
  }

  info(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('info', msgStr, contextObj);
  }

  warn(message: any, ...optionalParams: any[]): void {
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );
    this.callWinston('warn', msgStr, contextObj);
  }

  error(message: any, ...optionalParams: any[]): void {
    // NestJS thường gửi stack trace ở tham số thứ 2 hoặc 3
    const { msgStr, contextObj } = this.normalizeParams(
      message,
      ...optionalParams,
    );

    // Tìm Error object nếu có trong params
    const errorObj = optionalParams.find((p) => p instanceof Error);
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

  private callWinston(
    level: string,
    message: string,
    context?: LogContext,
  ): void {
    this.winstonLogger.log(level, message, {
      ...this.context,
      ...this.getTraceInfo(),
      ...context,
    });
  }
}
