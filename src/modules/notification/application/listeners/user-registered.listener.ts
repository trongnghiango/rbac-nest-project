import { Injectable } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { UserCreatedEvent } from '@modules/user/domain/events/user-created.event';
import { NotificationService } from '../services/notification.service';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
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
    this.logger.info(
      `📢 [EVENT RECEIVED] UserCreated: ${user.username} (ID: ${user.id})`,
    );

    // Gọi Service để xử lý nghiệp vụ
    if (user.email && user.id) {
      await this.notificationService.sendWelcomeEmail(
        user.id,
        user.email,
        user.username,
      );
    }
  }
}
