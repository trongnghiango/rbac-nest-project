import { Session } from '../../../domain/entities/session.entity';
import { SessionOrmEntity } from '../entities/session.orm-entity';

export class SessionMapper {
  static toDomain(orm: SessionOrmEntity | null): Session | null {
    if (!orm) return null;
    return new Session(
      orm.id,
      Number(orm.userId),
      orm.token,
      orm.expiresAt,
      orm.ipAddress || undefined, // Null -> Undefined
      orm.userAgent || undefined,
      orm.createdAt,
    );
  }

  static toPersistence(domain: Session): SessionOrmEntity {
    const orm = new SessionOrmEntity();
    if (domain.id) orm.id = domain.id;
    orm.userId = domain.userId;
    orm.token = domain.token;
    orm.expiresAt = domain.expiresAt;
    // FIX: Convert undefined -> null
    orm.ipAddress = domain.ipAddress || null;
    orm.userAgent = domain.userAgent || null;

    orm.createdAt = domain.createdAt || new Date();
    return orm;
  }
}
