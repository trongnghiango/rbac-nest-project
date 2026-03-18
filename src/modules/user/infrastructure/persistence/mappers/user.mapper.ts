
import { InferInsertModel } from 'drizzle-orm';
import { User } from '../../../domain/entities/user.entity';
import { users } from '@database/schema';

// Type insert cho bảng users (flat)
type UserInsert = InferInsertModel<typeof users>;

export class UserMapper {
  /**
   * Map từ kết quả query Drizzle (có Relation) sang Domain Entity
   * `raw` ở đây là `any` vì type của Drizzle Query Builder rất phức tạp để define tĩnh
   */
  static toDomain(raw: any): User | null {
    if (!raw) return null;

    // ✅ Logic Strict RBAC: Map từ bảng nối ra mảng string
    const roles: string[] = raw.userRoles
      ? raw.userRoles.map((ur: any) => ur.role?.name || '').filter(Boolean)
      : [];

    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive ?? true,
      roles, // ✅ Inject Roles
      raw.telegramId || undefined, // ✅ Inject TelegramId
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  /**
   * Map từ Domain sang Persistence (Chỉ map các field thuộc bảng `users`)
   * Không map `roles` vì roles nằm ở bảng `user_roles`
   */
  static toPersistence(domain: User): UserInsert {
    return {
      id: domain.id,
      username: domain.username,
      email: domain.email || null,
      hashedPassword: domain.hashedPassword || null,
      isActive: domain.isActive,
      telegramId: domain.telegramId || null, // ✅ Map TelegramId
      createdAt: domain.createdAt || new Date(),
      updatedAt: domain.updatedAt || new Date(),
    };
  }
}