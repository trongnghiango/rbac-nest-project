#!/bin/bash

# ============================================
# FIX LOGGING MIDDLEWARE TYPES
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🛠️ FIXING REQUEST LOGGING MIDDLEWARE..."

cat > src/api/middleware/request-logging.middleware.ts << 'EOF'
import { Injectable, NestMiddleware, Inject } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
// FIX 1: Dùng 'import type' để tránh lỗi TS1272
import type { ILogger } from '../../core/shared/application/ports/logger.port';

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  constructor(@Inject('ILogger') private readonly logger: ILogger) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();

    // FIX 2: Xử lý an toàn cho header (string | string[])
    let rawRequestId = req.headers['x-request-id'];
    if (Array.isArray(rawRequestId)) {
      rawRequestId = rawRequestId[0];
    }
    const requestId = rawRequestId || `req-${Date.now()}`;

    // Attach Request ID (đảm bảo là string)
    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);

    // Log Request
    this.logger.info(`Incoming Request: ${req.method} ${req.originalUrl}`, {
      requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Intercept Response finish
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const statusCode = res.statusCode;

      const message = `Request Completed: ${statusCode} (${duration}ms)`;
      const context = {
        requestId,
        statusCode,
        duration,
      };

      // FIX 3: Gọi tường minh các hàm log thay vì truy cập động
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

success "✅ MIDDLEWARE TYPES FIXED!"
echo "👉 Server should compile successfully now."