#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🚀 GENERATING NOTIFICATION MODULE (CLEAN ARCHITECTURE)..."

BASE_DIR="src/modules/notification"
mkdir -p $BASE_DIR/domain/{entities,repositories,enums}
mkdir -p $BASE_DIR/application/{services,listeners,ports}
mkdir -p $BASE_DIR/infrastructure/{persistence,persistence/mappers,adapters,controllers}
mkdir -p src/database/schema

# ==========================================
# 1. DOMAIN LAYER
# ==========================================

log "1️⃣ Creating Domain Layer..."

# Enum
cat > $BASE_DIR/domain/enums/notification.enum.ts << 'EOF'
export enum NotificationType {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  PUSH = 'PUSH',
}

export enum NotificationStatus {
  PENDING = 'PENDING',
  SENT = 'SENT',
  FAILED = 'FAILED',
}
EOF

# Entity
cat > $BASE_DIR/domain/entities/notification.entity.ts << 'EOF'
import { NotificationType, NotificationStatus } from '../enums/notification.enum';

export class Notification {
  constructor(
    public id: number | undefined,
    public userId: number,
    public type: NotificationType,
    public subject: string,
    public content: string,
    public status: NotificationStatus = NotificationStatus.PENDING,
    public sentAt?: Date,
    public createdAt?: Date,
  ) {}

  markAsSent() {
    this.status = NotificationStatus.SENT;
    this.sentAt = new Date();
  }

  markAsFailed() {
    this.status = NotificationStatus.FAILED;
  }
}
EOF

# Repository Port
cat > $BASE_DIR/domain/repositories/notification.repository.ts << 'EOF'
import { Notification } from '../entities/notification.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const INotificationRepository = Symbol('INotificationRepository');

export interface INotificationRepository {
  save(notification: Notification, tx?: Transaction): Promise<Notification>;
  findByUserId(userId: number): Promise<Notification[]>;
}
EOF

# ==========================================
# 2. APPLICATION LAYER
# ==========================================

log "2️⃣ Creating Application Layer..."

# Email Sender Port (Interface cho việc gửi mail)
cat > $BASE_DIR/application/ports/email-sender.port.ts << 'EOF'
export const IEmailSender = Symbol('IEmailSender');

export interface IEmailSender {
  send(to: string, subject: string, body: string): Promise<boolean>;
}
EOF

# Service (Use Cases)
cat > $BASE_DIR/application/services/notification.service.ts << 'EOF'
import { Injectable, Inject } from '@nestjs/common';
import { INotificationRepository } from '../../domain/repositories/notification.repository';
import { IEmailSender } from '../ports/email-sender.port';
import { Notification } from '../../domain/entities/notification.entity';
import { NotificationType } from '../../domain/enums/notification.enum';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Injectable()
export class NotificationService {
  constructor(
    @Inject(INotificationRepository) private readonly repo: INotificationRepository,
    @Inject(IEmailSender) private readonly emailSender: IEmailSender,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  async sendWelcomeEmail(userId: number, email: string, username: string): Promise<void> {
    this.logger.info(`Processing welcome email for user: ${userId}`);

    // 1. Tạo Entity (Pending)
    const notification = new Notification(
      undefined,
      userId,
      NotificationType.EMAIL,
      'Welcome to RBAC System',
      `Hello ${username}, welcome aboard!`,
    );

    // 2. Lưu vào DB
    const savedNotif = await this.repo.save(notification);

    // 3. Gửi Email thật (qua Adapter)
    const sent = await this.emailSender.send(email, savedNotif.subject, savedNotif.content);

    // 4. Update trạng thái
    if (sent) {
      savedNotif.markAsSent();
    } else {
      savedNotif.markAsFailed();
    }

    await this.repo.save(savedNotif);
    this.logger.info(`Notification processed. Status: ${savedNotif.status}`);
  }

  async getUserNotifications(userId: number) {
    return this.repo.findByUserId(userId);
  }
}
EOF

# Listener (Đây là nơi TEST EVENT BUS)
# Cần đảm bảo file UserCreatedEvent tồn tại. Tôi sẽ tạo dummy nếu chưa có.
mkdir -p src/modules/user/domain/events
if [ ! -f src/modules/user/domain/events/user-created.event.ts ]; then
    log "⚠️ Creating dummy UserCreatedEvent for compilation..."
    cat > src/modules/user/domain/events/user-created.event.ts << 'EOF'
import { IDomainEvent } from '@core/shared/domain/events/domain-event.interface';
import { User } from '../entities/user.entity';

export class UserCreatedEvent implements IDomainEvent {
  readonly eventName = 'UserCreated';
  readonly occurredAt = new Date();
  constructor(
    public readonly aggregateId: string,
    public readonly payload: { user: User }
  ) {}
}
EOF
fi

cat > $BASE_DIR/application/listeners/user-registered.listener.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { UserCreatedEvent } from '@modules/user/domain/events/user-created.event';
import { NotificationService } from '../services/notification.service';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';
import { Inject } from '@nestjs/common';

@Injectable()
export class UserRegisteredListener {
  constructor(
    private readonly notificationService: NotificationService,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  @EventHandler(UserCreatedEvent)
  async handleUserCreated(event: UserCreatedEvent) {
    const { user } = event.payload;
    this.logger.info(`📢 [EVENT RECEIVED] UserCreated: ${user.username} (ID: ${user.id})`);

    // Gọi Service để xử lý nghiệp vụ
    if (user.email && user.id) {
        await this.notificationService.sendWelcomeEmail(user.id, user.email, user.username);
    }
  }
}
EOF

# ==========================================
# 3. INFRASTRUCTURE LAYER
# ==========================================

log "3️⃣ Creating Infrastructure Layer..."

# Drizzle Schema
cat > src/database/schema/notifications.schema.ts << 'EOF'
import { pgTable, serial, text, timestamp, integer, boolean } from 'drizzle-orm/pg-core';

export const notifications = pgTable('notifications', {
  id: serial('id').primaryKey(),
  userId: integer('userId').notNull(), // Liên kết lỏng với bảng Users
  type: text('type').notNull(), // EMAIL, SMS
  subject: text('subject').notNull(),
  content: text('content').notNull(),
  status: text('status').notNull(), // PENDING, SENT
  sentAt: timestamp('sentAt'),
  createdAt: timestamp('createdAt').defaultNow(),
});
EOF

# Update index schema
# Lưu ý: Script này append vào cuối file, bạn nên kiểm tra lại nếu bị duplicate
if ! grep -q "notifications.schema" src/database/schema/index.ts; then
  echo "export * from './notifications.schema';" >> src/database/schema/index.ts
fi

# Mapper
cat > $BASE_DIR/infrastructure/persistence/mappers/notification.mapper.ts << 'EOF'
import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import { Notification } from '../../../domain/entities/notification.entity';
import { NotificationType, NotificationStatus } from '../../../domain/enums/notification.enum';
import { notifications } from '@database/schema';

type NotificationSelect = InferSelectModel<typeof notifications>;
type NotificationInsert = InferInsertModel<typeof notifications>;

export class NotificationMapper {
  static toDomain(raw: NotificationSelect | null): Notification | null {
    if (!raw) return null;
    return new Notification(
      raw.id,
      raw.userId,
      raw.type as NotificationType,
      raw.subject,
      raw.content,
      raw.status as NotificationStatus,
      raw.sentAt || undefined,
      raw.createdAt || undefined,
    );
  }

  static toPersistence(domain: Notification): NotificationInsert {
    return {
      id: domain.id,
      userId: domain.userId,
      type: domain.type,
      subject: domain.subject,
      content: domain.content,
      status: domain.status,
      sentAt: domain.sentAt || null,
      createdAt: domain.createdAt || new Date(),
    };
  }
}
EOF

# Drizzle Repository Implementation
cat > $BASE_DIR/infrastructure/persistence/drizzle-notification.repository.ts << 'EOF'
import { Injectable } from '@nestjs/common';
import { eq, desc } from 'drizzle-orm';
import { INotificationRepository } from '../../domain/repositories/notification.repository';
import { Notification } from '../../domain/entities/notification.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { notifications } from '@database/schema';
import { NotificationMapper } from './mappers/notification.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleNotificationRepository extends DrizzleBaseRepository implements INotificationRepository {

  async save(notification: Notification, tx?: Transaction): Promise<Notification> {
    const db = this.getDb(tx);
    const data = NotificationMapper.toPersistence(notification);

    let result;
    if (data.id) {
       result = await db.update(notifications)
        .set(data)
        .where(eq(notifications.id, data.id))
        .returning();
    } else {
       const { id, ...insertData } = data;
       result = await db.insert(notifications)
        .values(insertData as typeof notifications.$inferInsert)
        .returning();
    }
    return NotificationMapper.toDomain(result[0])!;
  }

  async findByUserId(userId: number): Promise<Notification[]> {
    const results = await this.db.select()
        .from(notifications)
        .where(eq(notifications.userId, userId))
        .orderBy(desc(notifications.createdAt));
    return results.map(r => NotificationMapper.toDomain(r)!);
  }
}
EOF

# Mock Email Adapter (Giả lập gửi email)
cat > $BASE_DIR/infrastructure/adapters/console-email.adapter.ts << 'EOF'
import { Injectable, Inject } from '@nestjs/common';
import { IEmailSender } from '../../application/ports/email-sender.port';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Injectable()
export class ConsoleEmailAdapter implements IEmailSender {
  constructor(@Inject(LOGGER_TOKEN) private readonly logger: ILogger) {}

  async send(to: string, subject: string, body: string): Promise<boolean> {
    // Giả lập độ trễ mạng
    await new Promise(resolve => setTimeout(resolve, 500));

    this.logger.info(`📧 [MOCK EMAIL SENT] To: ${to} | Subject: ${subject}`);
    this.logger.debug(`Body: ${body}`);

    return true; // Luôn thành công
  }
}
EOF

# Controller (Để test xem lại lịch sử)
cat > $BASE_DIR/infrastructure/controllers/notification.controller.ts << 'EOF'
import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { CurrentUser } from '@modules/auth/infrastructure/decorators/current-user.decorator';
import { User } from '@modules/user/domain/entities/user.entity';
import { NotificationService } from '../../application/services/notification.service';

@ApiTags('Notifications')
@ApiBearerAuth()
@Controller('notifications')
@UseGuards(JwtAuthGuard)
export class NotificationController {
  constructor(private readonly service: NotificationService) {}

  @ApiOperation({ summary: 'Get my notifications' })
  @Get()
  async getMyNotifications(@CurrentUser() user: User) {
    if (!user.id) return [];
    return this.service.getUserNotifications(user.id);
  }
}
EOF

# ==========================================
# 4. MODULE ASSEMBLY
# ==========================================

log "4️⃣ Creating Notification Module..."

cat > $BASE_DIR/notification.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { NotificationService } from './application/services/notification.service';
import { UserRegisteredListener } from './application/listeners/user-registered.listener';
import { NotificationController } from './infrastructure/controllers/notification.controller';
import { DrizzleNotificationRepository } from './infrastructure/persistence/drizzle-notification.repository';
import { INotificationRepository } from './domain/repositories/notification.repository';
import { ConsoleEmailAdapter } from './infrastructure/adapters/console-email.adapter';
import { IEmailSender } from './application/ports/email-sender.port';

@Module({
  controllers: [NotificationController],
  providers: [
    NotificationService,
    UserRegisteredListener, // Đăng ký Listener để EventBus Explorer quét được
    {
      provide: INotificationRepository,
      useClass: DrizzleNotificationRepository,
    },
    {
      provide: IEmailSender,
      useClass: ConsoleEmailAdapter, // Có thể đổi thành SES/SendGridAdapter sau này
    },
  ],
  exports: [NotificationService],
})
export class NotificationModule {}
EOF

success "✅ NOTIFICATION MODULE GENERATED!"
echo "👉 MANUAL STEP 1: Add 'NotificationModule' to 'imports' in 'src/bootstrap/app.module.ts'"
echo "👉 MANUAL STEP 2: Run DB Migration (or push schema) to create 'notifications' table."
echo "👉 MANUAL STEP 3: Ensure 'AuthenticationService.register' publishes 'UserCreatedEvent'."