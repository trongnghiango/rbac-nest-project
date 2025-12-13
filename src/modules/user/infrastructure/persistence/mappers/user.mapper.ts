import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
// FIX PATH: 3 dots ../../../
import { User } from '../../../domain/entities/user.entity';
import { users } from '@database/schema';

type UserSelect = InferSelectModel<typeof users>;
type UserInsert = InferInsertModel<typeof users>;

export class UserMapper {
  static toDomain(raw: UserSelect | null): User | null {
    if (!raw) return null;
    return new User(
      raw.id,
      raw.username,
      raw.email || undefined,
      raw.hashedPassword || undefined,
      raw.fullName || undefined,
      raw.isActive ?? true,
      raw.phoneNumber || undefined,
      raw.avatarUrl || undefined,
      (raw.profile as any) || undefined,
      raw.createdAt || undefined,
      raw.updatedAt || undefined,
    );
  }

  static toPersistence(domain: User): UserInsert {
    return {
      id: domain.id,
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
