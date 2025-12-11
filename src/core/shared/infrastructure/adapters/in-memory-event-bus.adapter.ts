import { Injectable, Logger } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port'; // ../../ trỏ về src/core/shared
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class InMemoryEventBus implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBus.name);
  private handlers = new Map<string, Function[]>();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName);

    if (handlers) {
      this.logger.debug(`Publishing event: ${eventName}`);
      await Promise.all(handlers.map(handler => handler(event)));
    }
  }

  async publishAll(events: IDomainEvent[]): Promise<void> {
    await Promise.all(events.map(event => this.publish(event)));
  }

  subscribe<T extends IDomainEvent>(eventName: string, handler: (event: T) => Promise<void>): void {
    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)?.push(handler);
  }

  unsubscribe(eventName: string, handler: Function): void {
    const handlers = this.handlers.get(eventName);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }
}
