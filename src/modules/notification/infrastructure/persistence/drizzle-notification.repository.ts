import { Inject, Injectable } from '@nestjs/common';
import { eq, desc, InferSelectModel } from 'drizzle-orm'; // 1. Import InferSelectModel
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { DRIZZLE } from '@database/drizzle.provider';
import {
  ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { INotificationRepository } from '../../domain/repositories/notification.repository';
import { Notification } from '../../domain/entities/notification.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { notifications } from '@database/schema';
import { NotificationMapper } from './mappers/notification.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 2. Định nghĩa kiểu trả về từ DB để tránh 'any'
type NotificationRecord = InferSelectModel<typeof notifications>;

@Injectable()
export class DrizzleNotificationRepository
  extends DrizzleBaseRepository
  implements INotificationRepository {
  constructor(
    @Inject(DRIZZLE) db: NodePgDatabase<typeof schema>,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {
    super(db);
  }

  async save(
    notification: Notification,
    tx?: Transaction,
  ): Promise<Notification> {
    const db = this.getDb();
    const data = NotificationMapper.toPersistence(notification);

    // 3. Khai báo kiểu rõ ràng cho result -> Fix lỗi "Variable implicitly has an 'any' type"
    let result: NotificationRecord[];

    if (data.id) {
      result = await db
        .update(notifications)
        .set(data)
        .where(eq(notifications.id, data.id))
        .returning();
    } else {
      // 4. Fix lỗi "'id' assigned but never used": Đổi tên thành '_id' (quy ước biến không dùng)
      const { id: _id, ...insertData } = data;

      // 5. Fix lỗi "Assertion is unnecessary": Bỏ đoạn 'as typeof ...'
      result = await db.insert(notifications).values(insertData).returning();
    }

    // FIX: Kiểm tra kết quả trả về thay vì dùng '!'
    const mapped = NotificationMapper.toDomain(result[0]);

    // Nếu mapper trả về null (trường hợp hiếm), ném lỗi để crash sớm thay vì trả về null sai type
    if (!mapped) {
      throw new Error('Failed to map notification result from DB');
    }

    return mapped;
  }

  async findByUserId(userId: number): Promise<Notification[]> {
    // 7. Đảm bảo biến userId được sử dụng trong câu query
    const results = await this.db
      .select()
      .from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt));

    // 8. Format code để fix lỗi Prettier
    // return results.map((r) => NotificationMapper.toDomain(r)!);
    // FIX: Map dữ liệu và lọc bỏ null một cách an toàn (Type Guard)
    return results
      .map((r) => NotificationMapper.toDomain(r))
      .filter((n): n is Notification => n !== null);
  }
}
