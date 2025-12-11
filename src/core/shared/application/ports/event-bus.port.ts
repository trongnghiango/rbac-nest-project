import { IDomainEvent } from '../../domain/events/domain-event.interface';

export interface IEventBus {
  publish<T extends IDomainEvent>(event: T): Promise<void>;
  publishAll(events: IDomainEvent[]): Promise<void>;
  subscribe<T extends IDomainEvent>(eventName: string, handler: (event: T) => Promise<void>): void;
  unsubscribe(eventName: string, handler: Function): void;
}
