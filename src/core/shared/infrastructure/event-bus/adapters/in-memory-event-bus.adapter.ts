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
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName) || [];

    Promise.all(handlers.map((handler) => handler(event))).catch((err) =>
      this.logger.error(`Error handling event ${eventName}`, err),
    );
  }

  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>,
  ): void {
    let eventName: string;

    if (typeof eventCls === 'string') {
      eventName = eventCls;
    } else {
      // ✅ SAFE FIX: Sử dụng Object.create để tránh gọi constructor thực thi logic validate
      // Điều này ngăn chặn crash app khi khởi tạo Event Class rỗng
      const instance = Object.create(eventCls.prototype);
      // Nếu eventName là property instance (được gán trong constructor), ta không lấy được ở đây
      // NHƯNG, với kiến trúc hiện tại, eventName thường hardcode.
      // Cách tốt nhất: Fallback về tên Class nếu instance.eventName undefined
      eventName = instance.eventName || eventCls.name;

      // Nếu trường hợp eventName bắt buộc phải lấy từ instance thật và khác tên class
      // thì nên refactor Event thành có static property.
      // Ở đây ta dùng instance giả lập an toàn.
      if (!eventName) {
        try {
          const realInstance = new eventCls({} as any, {} as any);
          eventName = realInstance.eventName;
        } catch (e) {
          eventName = eventCls.name;
          this.logger.warn(
            `Could not extract eventName from ${eventCls.name}, using class name.`,
          );
        }
      }
    }

    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)!.push(handler as any);
    this.logger.log(`Subscribed to event: ${eventName}`);
  }
}
