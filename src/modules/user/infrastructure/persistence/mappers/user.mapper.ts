import { User } from '../../../domain/entities/user.entity';
import { UserOrmEntity } from '../entities/user.orm-entity';

export class UserMapper {
  static toDomain(ormEntity: UserOrmEntity | null): User | null {
    if (!ormEntity) return null;

    return new User(
      Number(ormEntity.id),
      ormEntity.username,
      ormEntity.email || undefined,
      ormEntity.hashedPassword || undefined,
      ormEntity.fullName || undefined,
      ormEntity.isActive,
      ormEntity.phoneNumber || undefined,
      ormEntity.avatarUrl || undefined,
      ormEntity.profile || undefined,
      ormEntity.createdAt,
      ormEntity.updatedAt,
    );
  }

  static toPersistence(domainEntity: User): UserOrmEntity {
    const ormEntity = new UserOrmEntity();
    if (domainEntity.id !== undefined) {
      ormEntity.id = domainEntity.id;
    }
    ormEntity.username = domainEntity.username;
    ormEntity.email = domainEntity.email || null;
    ormEntity.hashedPassword = domainEntity.hashedPassword || null;
    ormEntity.fullName = domainEntity.fullName || null;
    ormEntity.isActive = domainEntity.isActive;
    ormEntity.phoneNumber = domainEntity.phoneNumber || null;
    ormEntity.avatarUrl = domainEntity.avatarUrl || null;
    ormEntity.profile = domainEntity.profile || null;

    ormEntity.createdAt = domainEntity.createdAt || new Date();
    ormEntity.updatedAt = domainEntity.updatedAt || new Date();
    return ormEntity;
  }
}
