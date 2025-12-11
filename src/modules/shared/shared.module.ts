import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmTransactionManager } from '../../core/shared/infrastructure/persistence/typeorm-transaction.manager';
import { InMemoryEventBus } from '../../core/shared/infrastructure/adapters/in-memory-event-bus.adapter';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
  providers: [
    {
      provide: 'ITransactionManager',
      useClass: TypeOrmTransactionManager,
    },
    {
      provide: 'IEventBus',
      useClass: InMemoryEventBus,
    }
  ],
  exports: [ConfigModule, 'ITransactionManager', 'IEventBus'],
})
export class SharedModule {}
