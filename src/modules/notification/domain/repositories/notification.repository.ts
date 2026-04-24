import { Notification } from '../entities/notification.entity';

export const INotificationRepository = Symbol('INotificationRepository');

export interface INotificationRepository {
  save(notification: Notification): Promise<Notification>;
  findByUserId(userId: number): Promise<Notification[]>;
}
