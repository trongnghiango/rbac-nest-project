import { IDomainEvent } from '../../domain/events/domain-event.interface';
import { Type } from '@nestjs/common';

export const IEventBus = Symbol('IEventBus');

export interface IEventBus {
  publish<T extends IDomainEvent>(event: T): Promise<void>;

  // Hàm này dùng cho cơ chế Auto-Discovery đăng ký handler
  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>,
  ): void;
}
