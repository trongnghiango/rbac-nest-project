import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DrizzleTransactionManager } from '@core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '@database/drizzle.module';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { EventBusModule } from '@core/shared/infrastructure/event-bus/event-bus.module';
import { CsvParserAdapter } from '@core/shared/infrastructure/adapters/csv-parser.adapter';
import { IFileParser } from '@core/shared/application/ports/file-parser.port';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    DrizzleModule,
    EventBusModule,
  ],
  providers: [
    {
      provide: ITransactionManager,
      useClass: DrizzleTransactionManager,
    },
    {
      provide: IFileParser,
      useClass: CsvParserAdapter,
    },
  ],
  exports: [ConfigModule, ITransactionManager, EventBusModule, IFileParser],
})
export class SharedModule {}
