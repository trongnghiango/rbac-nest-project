#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🚀 STARTING PRO EVENT BUS ARCHITECTURE SETUP..."

# 1. Tạo thư mục cấu trúc
DIR="src/core/shared/infrastructure/event-bus"
mkdir -p $DIR/adapters
mkdir -p $DIR/decorators

# 2. Định nghĩa Event Bus Port (Interface)
# Lưu ý: Ta thêm method subscribe để Adapter implement việc lắng nghe
log "🔌 Creating EventBus Port..."
cat > src/core/shared/application/ports/event-bus.port.ts << 'EOF'
import { IDomainEvent } from '../../domain/events/domain-event.interface';
import { Type } from '@nestjs/common';

export const IEventBus = Symbol('IEventBus');

export interface IEventBus {
  publish<T extends IDomainEvent>(event: T): Promise<void>;

  // Hàm này dùng cho cơ chế Auto-Discovery đăng ký handler
  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>
  ): void;
}
EOF

# 3. Tạo Decorator @EventHandler (Cái này tạo nên độ PRO)
log "✨ Creating @EventHandler Decorator..."
cat > $DIR/decorators/event-handler.decorator.ts << 'EOF'
import { SetMetadata } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { IDomainEvent } from '../../../domain/events/domain-event.interface';

export const EVENT_HANDLER_METADATA = 'EVENT_HANDLER_METADATA';

// Decorator này dùng để đánh dấu method nào sẽ xử lý event nào
export const EventHandler = (event: Type<IDomainEvent> | string) =>
  SetMetadata(EVENT_HANDLER_METADATA, event);
EOF

# 4. Implement InMemory Adapter (Mặc định)
log "🧠 Creating In-Memory Adapter..."
cat > $DIR/adapters/in-memory-event-bus.adapter.ts << 'EOF'
import { Injectable, Logger } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port';
import { IDomainEvent } from '../../domain/events/domain-event.interface';
import { Type } from '@nestjs/common';

@Injectable()
export class InMemoryEventBusAdapter implements IEventBus {
  private readonly logger = new Logger(InMemoryEventBusAdapter.name);
  private handlers = new Map<string, Array<(event: IDomainEvent) => Promise<void>>>();

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const eventName = event.eventName;
    const handlers = this.handlers.get(eventName) || [];

    // Chạy bất đồng bộ, không block main thread
    Promise.all(handlers.map(handler => handler(event)))
      .catch(err => this.logger.error(`Error handling event ${eventName}`, err));
  }

  subscribe<T extends IDomainEvent>(
    eventCls: Type<T> | string,
    handler: (event: T) => Promise<void>
  ): void {
    // Nếu truyền vào Class, ta lấy tên instance giả định hoặc static property
    // Ở đây ta thống nhất dùng eventName string làm key
    const eventName = typeof eventCls === 'string'
      ? eventCls
      : new eventCls({} as any, {} as any).eventName; // Hack nhẹ để lấy eventName từ class rỗng

    if (!this.handlers.has(eventName)) {
      this.handlers.set(eventName, []);
    }
    this.handlers.get(eventName)!.push(handler as any);
    this.logger.log(`Subscribed to event: ${eventName}`);
  }
}
EOF

# 5. Implement RabbitMQ Adapter (Skeleton)
log "🐰 Creating RabbitMQ Adapter Skeleton..."
cat > $DIR/adapters/rabbitmq-event-bus.adapter.ts << 'EOF'
import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port';
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class RabbitMQEventBusAdapter implements IEventBus, OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RabbitMQEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to RabbitMQ...');
    // TODO: Implement connection logic using amqplib or nestjs/microservices
  }

  async onModuleDestroy() {
    this.logger.log('Closing RabbitMQ connection...');
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    this.logger.log(`[RabbitMQ] Publishing: ${event.eventName}`);
    // TODO: channel.publish(exchange, routingKey, Buffer.from(JSON.stringify(event)))
  }

  subscribe<T extends IDomainEvent>(eventCls: any, handler: (event: T) => Promise<void>): void {
    this.logger.log(`[RabbitMQ] Subscribing to: ${eventCls}`);
    // TODO: channel.consume(queue, (msg) => handler(JSON.parse(msg.content)))
  }
}
EOF

# 6. Implement Kafka Adapter (Skeleton)
log "🐘 Creating Kafka Adapter Skeleton..."
cat > $DIR/adapters/kafka-event-bus.adapter.ts << 'EOF'
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { IEventBus } from '../../application/ports/event-bus.port';
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class KafkaEventBusAdapter implements IEventBus, OnModuleInit {
  private readonly logger = new Logger(KafkaEventBusAdapter.name);

  async onModuleInit() {
    this.logger.log('Connecting to Kafka...');
    // TODO: Implement connection logic using kafkajs
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    this.logger.log(`[Kafka] Publishing: ${event.eventName}`);
    // TODO: producer.send({ topic, messages: [{ value: JSON.stringify(event) }] })
  }

  subscribe<T extends IDomainEvent>(eventCls: any, handler: (event: T) => Promise<void>): void {
    this.logger.log(`[Kafka] Subscribing to: ${eventCls}`);
    // TODO: consumer.subscribe({ topic }); consumer.run({ eachMessage: ... })
  }
}
EOF

# 7. Tạo Event Explorer (Discovery Service)
# Đây là thành phần quan trọng để tự động tìm các @EventHandler
log "🔍 Creating Event Explorer (Auto-Discovery)..."
cat > $DIR/event.explorer.ts << 'EOF'
import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import { IEventBus } from '../../application/ports/event-bus.port';
import { EVENT_HANDLER_METADATA } from './decorators/event-handler.decorator';
import { IDomainEvent } from '../../domain/events/domain-event.interface';

@Injectable()
export class EventExplorer implements OnModuleInit {
  constructor(
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly reflector: Reflector,
    @Inject(IEventBus) private readonly eventBus: IEventBus,
  ) {}

  onModuleInit() {
    this.explore();
  }

  private explore() {
    // Lấy tất cả các providers (Service, Controller...) trong app
    const providers = this.discoveryService.getProviders();

    providers
      .filter((wrapper) => wrapper.instance && !wrapper.isAlias)
      .forEach((wrapper) => {
        const { instance } = wrapper;
        const prototype = Object.getPrototypeOf(instance);
        if (!prototype) return;

        // Quét tất cả các method của instance
        this.metadataScanner.scanFromPrototype(
          instance,
          prototype,
          (methodName) => {
            const method = instance[methodName];
            // Kiểm tra xem method có gắn @EventHandler không
            const eventCls = this.reflector.get(EVENT_HANDLER_METADATA, method);

            if (eventCls) {
              // Đăng ký method đó vào EventBus
              this.eventBus.subscribe(eventCls, method.bind(instance));
            }
          },
        );
      });
  }
}
EOF

# 8. Tạo Config cho EventBus
log "⚙️ Creating EventBus Config..."
cat > src/config/event-bus.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('eventBus', () => ({
  // 'memory' | 'rabbitmq' | 'kafka'
  type: process.env.EVENT_BUS_TYPE || 'memory',
}));
EOF

# 9. Tạo EventBus Module (Dynamic Provider)
log "📦 Creating EventBus Module..."
cat > $DIR/event-bus.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DiscoveryModule } from '@nestjs/core'; // Cần thiết cho DiscoveryService
import { IEventBus } from '../../application/ports/event-bus.port';
import { InMemoryEventBusAdapter } from './adapters/in-memory-event-bus.adapter';
import { RabbitMQEventBusAdapter } from './adapters/rabbitmq-event-bus.adapter';
import { KafkaEventBusAdapter } from './adapters/kafka-event-bus.adapter';
import { EventExplorer } from './event.explorer';
import eventBusConfig from '@config/event-bus.config';

@Global()
@Module({
  imports: [
    ConfigModule.forFeature(eventBusConfig),
    DiscoveryModule, // Import để dùng DiscoveryService
  ],
  providers: [
    EventExplorer, // Đăng ký Explorer
    {
      provide: IEventBus,
      useFactory: (config: ConfigService) => {
        const type = config.get('eventBus.type');
        console.log(`🔌 EventBus initialized with type: ${type}`);

        switch (type) {
          case 'rabbitmq':
            return new RabbitMQEventBusAdapter();
          case 'kafka':
            return new KafkaEventBusAdapter();
          case 'memory':
          default:
            return new InMemoryEventBusAdapter();
        }
      },
      inject: [ConfigService],
    },
  ],
  exports: [IEventBus],
})
export class EventBusModule {}
EOF

# 10. Refactor Shared Module (Bỏ EventBus cũ, dùng Module mới)
log "🔄 Refactoring SharedModule..."
cat > src/modules/shared/shared.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DrizzleTransactionManager } from '@core/shared/infrastructure/persistence/drizzle-transaction.manager';
import { DrizzleModule } from '@database/drizzle.module';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { EventBusModule } from '@core/shared/infrastructure/event-bus/event-bus.module'; // Import Module Mới

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    DrizzleModule,
    EventBusModule, // ✅ Sử dụng EventBusModule chuyên biệt
  ],
  providers: [
    {
      provide: ITransactionManager,
      useClass: DrizzleTransactionManager,
    }
  ],
  exports: [ConfigModule, ITransactionManager, EventBusModule],
})
export class SharedModule {}
EOF

# 11. Cập nhật AppModule để load config
log "🔄 Updating AppModule..."
# (Giả định file app.module.ts của bạn đã có redisConfig từ bước trước)
# Chúng ta chỉ cần add eventBusConfig vào load list. Code dưới đây là ghi đè, hãy cẩn thận nếu bạn đã sửa tay nhiều.
# Để an toàn, tôi sẽ tạo file nhắc nhở add config thay vì overwrite.

log "📝 Appending EVENT_BUS_TYPE to .env..."
if ! grep -q "EVENT_BUS_TYPE" .env; then
  echo "" >> .env
  echo "# Event Bus Configuration (memory, rabbitmq, kafka)" >> .env
  echo "EVENT_BUS_TYPE=memory" >> .env
  success "✅ Added EVENT_BUS_TYPE to .env"
fi

success "✅ EVENT BUS REFACTORING COMPLETED!"
echo "👉 MANUAL STEP: Please add 'eventBusConfig' to 'ConfigModule.forRoot({ load: [...] })' in 'src/bootstrap/app.module.ts'"
echo "👉 Example usage in Service:"
echo "   @EventHandler(UserCreatedEvent)"
echo "   async handleUserCreated(event: UserCreatedEvent) { ... }"