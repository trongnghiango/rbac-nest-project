import { Module, DynamicModule, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WinstonFactory } from './infrastructure/winston/winston.factory';
import { WinstonLoggerAdapter } from './infrastructure/winston/winston-logger.adapter';
import { DrizzleAuditLogService } from './infrastructure/persistence/drizzle-audit-log.service';
// Import Token
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { AUDIT_LOG_PORT } from '@core/shared/application/ports/audit-log.port';

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
        {
          provide: AUDIT_LOG_PORT,
          useClass: DrizzleAuditLogService,
        },
      ],
      exports: [LOGGER_TOKEN, AUDIT_LOG_PORT], // ✅ Export cả Logger và AuditLog
    };
  }
}
