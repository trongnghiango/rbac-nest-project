import { InferSelectModel } from 'drizzle-orm';
import { User } from '../../../domain/entities/user.entity';
import { users } from '../../../../../database/schema';

// Tự động lấy Type từ Schema Definition
type UserRecord = InferSelectModel<typeof users>;

export class UserMapper {
  static toDomain(raw: UserRecord | null): User | null {
    if (!raw) return null;

    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive || false,
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined, // JSONB cần cast nhẹ hoặc định nghĩa type riêng
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: User) {
    return {
      id: domain.id, // Có thể undefined
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      fullName: domain.fullName || null,
      isActive: domain.isActive,
      phoneNumber: domain.phoneNumber || null,
      avatarUrl: domain.avatarUrl || null,
      profile: domain.profile || null,
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}
