import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { InMemoryEventBus } from '../../core/shared/infrastructure/adapters/in-memory-event-bus.adapter';
import { DrizzleTransactionManager } from '../../core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '../../database/drizzle.module';

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
      provide: 'ITransactionManager',
      useClass: DrizzleTransactionManager,
    },
  ],
  exports: [ConfigModule, 'IEventBus', 'ITransactionManager'],
})
export class SharedModule {}
