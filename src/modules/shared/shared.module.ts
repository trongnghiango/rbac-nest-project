import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { InMemoryEventBus } from '@core/shared/infrastructure/adapters/in-memory-event-bus.adapter';
import { DrizzleTransactionManager } from '@core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '@database/drizzle.module';
// FIX IMPORT
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    DrizzleModule,
  ],
  providers: [
    {
      provide: 'IEventBus',
      useClass: InMemoryEventBus,
    },
    {
      provide: ITransactionManager, // FIX: Use Symbol Token
      useClass: DrizzleTransactionManager,
    },
  ],
  exports: [ConfigModule, 'IEventBus', ITransactionManager], // FIX: Export Symbol Token
})
export class SharedModule {}
