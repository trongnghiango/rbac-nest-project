import { InferSelectModel } from 'drizzle-orm';
import { Session } from '../../../domain/entities/session.entity';
import { sessions } from '../../../../../database/schema';

type SessionRecord = InferSelectModel<typeof sessions>;

export class SessionMapper {
  static toDomain(raw: SessionRecord | null): Session | null {
    if (!raw) return null;
    return new Session(
      raw.id,
      Number(raw.userId),
      raw.token,
      raw.expiresAt,
      raw.ipAddress || undefined,
      raw.userAgent || undefined,
      raw.createdAt || undefined,
    );
  }

  static toPersistence(domain: Session) {
    return {
      id: domain.id, // UUID thì có thể truyền vào hoặc để DB tự gen
      userId: domain.userId,
      token: domain.token,
      expiresAt: domain.expiresAt,
      ipAddress: domain.ipAddress || null,
      userAgent: domain.userAgent || null,
      createdAt: domain.createdAt || new Date(),
    };
  }
}
