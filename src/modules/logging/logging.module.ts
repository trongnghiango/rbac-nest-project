import { Module, DynamicModule, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { WinstonFactory } from './infrastructure/winston/winston.factory';
import { WinstonLoggerAdapter } from './infrastructure/winston/winston-logger.adapter';
// Import Token
import { LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

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
