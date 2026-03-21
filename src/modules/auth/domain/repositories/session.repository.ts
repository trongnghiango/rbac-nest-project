import { Session } from '../entities/session.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const ISessionRepository = Symbol('ISessionRepository');

export interface ISessionRepository {
  create(session: Session, tx?: Transaction): Promise<void>;
  findByUserId(userId: number): Promise<Session[]>;
  deleteByUserId(userId: number): Promise<void>;

  findByRefreshToken(refreshToken: string): Promise<Session | null>;
  update(id: string, data: Partial<Session>, tx?: Transaction): Promise<void>;

  // 👉 THÊM tinh nang thu hoi Token - MỚI
  findByToken(token: string): Promise<Session | null>;
  deleteByToken(token: string): Promise<void>;
}
