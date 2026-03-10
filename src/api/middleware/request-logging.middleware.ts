import { Injectable, NestMiddleware, Inject } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import type { ILogger } from '@core/shared/application/ports/logger.port';
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import {
  RequestContextService,
  RequestContext,
} from '@core/shared/infrastructure/context/request-context.service';

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    let rawRequestId = req.headers['x-request-id'];
    if (Array.isArray(rawRequestId)) rawRequestId = rawRequestId[0];
    const requestId = rawRequestId || `req-${Date.now()}`;

    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);

    // QUAN TRỌNG: Bọc next() trong RequestContextService.run
    const context = new RequestContext(requestId, req.originalUrl);

    RequestContextService.run(context, () => {
      // Log lúc bắt đầu (bên trong context)
      this.logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      res.on('finish', () => {
        const duration = Date.now() - startTime;
        const statusCode = res.statusCode;
        const message = `Request Completed: ${statusCode} (${duration}ms)`;
        const logContext = { statusCode, duration };

        if (statusCode >= 500) {
          this.logger.error(message, undefined, logContext);
        } else if (statusCode >= 400) {
          this.logger.warn(message, logContext);
        } else {
          this.logger.info(message, logContext);
        }
      });

      next();
    });
  }
}
