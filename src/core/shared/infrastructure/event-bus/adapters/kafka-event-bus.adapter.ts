import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class KafkaEventBusAdapter implements IEventBus, OnModuleInit {
  private readonly logger = new Logger(KafkaEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to Kafka...');
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = (event.constructor as any).EVENT_NAME || event.constructor.name;
    this.logger.log(`[Kafka] Publishing: ${eventName} - Payload:`, event.payload);
  }

  subscribe<T extends IDomainEvent>(
    eventCls: any,
    handler: (event: T) => Promise<void>,
  ): void {
    this.logger.log(`[Kafka] Subscribing to: ${eventCls}`);
  }
}
