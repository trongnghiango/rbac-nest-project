#!/bin/bash

BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'
log() { echo -e "${BLUE}[INFO]${NC} $1"; }

log "🛠️ FIXING WINSTON IMPORT ERROR..."

cat > src/modules/logging/infrastructure/winston/winston.factory.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';

// FIX: Dùng require để tránh lỗi "is not a constructor" do xung đột ES Module/CommonJS
// eslint-disable-next-line @typescript-eslint/no-var-requires
const DailyRotateFile = require('winston-daily-rotate-file');

@Injectable()
export class WinstonFactory {
  constructor(private configService: ConfigService) {}

  createLogger(): winston.Logger {
    const logLevel = this.configService.get('logging.level') || 'info';
    const appName = this.configService.get('app.name') || 'SERVER';
    const isProduction = process.env.NODE_ENV === 'production';

    // 1. MASKER
    const sensitiveKeys = ['password', 'token', 'authorization', 'secret', 'creditCard', 'cvv'];
    const masker = winston.format((info) => {
      const maskDeep = (obj: any) => {
        if (!obj || typeof obj !== 'object') return;
        Object.keys(obj).forEach((key) => {
          if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
            obj[key] = '***MASKED***';
          } else if (typeof obj[key] === 'object') {
            maskDeep(obj[key]);
          }
        });
      };
      const splat = (info as any)[Symbol.for('splat')];
      if (splat) maskDeep(splat);
      maskDeep(info);
      return info;
    });

    // 2. CONSOLE FORMAT
    const consoleFormat = winston.format.printf((info) => {
      const tsVal = info.timestamp || new Date().toISOString();
      const { level, message, context, requestId, label, timestamp, ...meta } = info;

      const cDim = '\x1b[2m';
      const cReset = '\x1b[0m';
      const cCyan = '\x1b[36m';
      const cYellow = '\x1b[33m';

      const splatSymbol = Symbol.for('splat');
      const splat = (info as any)[splatSymbol];
      let finalMeta = { ...meta };
      if (Array.isArray(splat)) {
        const splatObj = splat.find((item: any) => typeof item === 'object' && item !== null);
        if (splatObj) Object.assign(finalMeta, splatObj);
      }

      delete (finalMeta as any).level;
      delete (finalMeta as any).message;
      delete (finalMeta as any).timestamp;
      delete (finalMeta as any).service;

      let metaStr = '';
      if (Object.keys(finalMeta).length) {
         const jsonStr = JSON.stringify(finalMeta);
         if (jsonStr.length < 150) {
             metaStr = ` ${cDim}${jsonStr}${cReset}`;
         } else {
             metaStr = `\n${cDim}${JSON.stringify(finalMeta, null, 2)}${cReset}`;
         }
      }

      const timeDisplay = `${cDim}[${tsVal}]${cReset}`;
      const levelDisplay = level;
      const contextVal = context || label || appName;
      const contextDisplay = `${cYellow}[${contextVal}]${cReset}`;
      const requestDisplay = requestId ? `${cCyan}[${requestId}]${cReset}` : '';

      return `${timeDisplay} ${levelDisplay} ${contextDisplay} ${requestDisplay} ${message}${metaStr}`;
    });

    // 3. TRANSPORTS
    const transports: winston.transport[] = [
      new DailyRotateFile({
        dirname: 'logs',
        filename: 'app-%DATE%.info.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '14d',
        level: 'info',
        format: winston.format.combine(winston.format.timestamp(), masker(), winston.format.json()),
      }),
      new DailyRotateFile({
        dirname: 'logs',
        filename: 'app-%DATE%.error.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        level: 'error',
        format: winston.format.combine(winston.format.timestamp(), masker(), winston.format.json()),
      }),
    ];

    if (isProduction) {
      transports.push(new winston.transports.Console({
        format: winston.format.combine(winston.format.timestamp(), masker(), winston.format.json()),
      }));
    } else {
      transports.push(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.timestamp({ format: 'HH:mm:ss' }),
            masker(),
            winston.format.colorize({ all: true }),
            consoleFormat
        ),
      }));
    }

    return winston.createLogger({
      level: logLevel,
      defaultMeta: { service: appName },
      transports,
      exitOnError: false,
    });
  }
}
EOF

echo "✅ FIXED: Replaced import with require for DailyRotateFile."
echo "👉 Restart server: npm run start:dev"