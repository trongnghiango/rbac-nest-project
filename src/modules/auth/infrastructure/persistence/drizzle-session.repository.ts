import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
// FIX IMPORT
import { ISessionRepository } from '../../domain/repositories/session.repository';
import { Session } from '../../domain/entities/session.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { sessions } from '@database/schema';
import { SessionMapper } from './mappers/session.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleSessionRepository
  extends DrizzleBaseRepository
  implements ISessionRepository
{
  async create(session: Session, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    const data = SessionMapper.toPersistence(session);

    if (data.id) {
      await db.insert(sessions).values(data as any);
    } else {
      const { id, ...insertData } = data;
      await db
        .insert(sessions)
        .values(insertData as typeof sessions.$inferInsert);
    }
  }

  async findByUserId(userId: number): Promise<Session[]> {
    const results = await this.db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId));
    return results.map((r) => SessionMapper.toDomain(r)!);
  }

  async deleteByUserId(userId: number): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.userId, userId));
  }
}
