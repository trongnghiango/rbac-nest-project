import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class RabbitMQEventBusAdapter
  implements IEventBus, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RabbitMQEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to RabbitMQ...');
  }

  async onModuleDestroy() {
    this.logger.log('Closing RabbitMQ connection...');
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = (event.constructor as any).EVENT_NAME || event.constructor.name;
    this.logger.log(`[RabbitMQ] Publishing: ${eventName} - Payload:`, event.payload);

  }

  subscribe<T extends IDomainEvent>(
    eventCls: any,
    handler: (event: T) => Promise<void>,
  ): void {
    this.logger.log(`[RabbitMQ] Subscribing to: ${eventCls}`);
  }
}
