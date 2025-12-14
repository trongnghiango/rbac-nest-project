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
