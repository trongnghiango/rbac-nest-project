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
