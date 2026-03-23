import { Injectable, Logger } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';

@Injectable()
export class InMemoryEventBusAdapter implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBusAdapter.name);
  private handlers = new Map<
    string,
    Array<(event: IDomainEvent) => Promise<void>>
  >();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    // 👉 Lấy tên Event một cách an toàn từ instance: 
    // Ưu tiên biến static EVENT_NAME, nếu không có thì lấy tên của Class (VD: "UserCreatedEvent")
    const eventName = (event.constructor as any).EVENT_NAME || event.constructor.name;
    const handlers = this.handlers.get(eventName) || [];

    Promise.all(handlers.map((handler) => handler(event))).catch((err) =>
      this.logger.error(`Error handling event ${eventName}`, err),
    );
  }

  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>,
  ): void {
    // 👉 ĐỌC TÊN EVENT TRỰC TIẾP TỪ CLASS (KHÔNG CẦN KHỞI TẠO OBJECT)
    const eventName = typeof eventCls === 'string'
      ? eventCls
      : (eventCls as any).EVENT_NAME || eventCls.name;

    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)!.push(handler as any);
    this.logger.log(`Subscribed to event: ${eventName}`);
  }
}
