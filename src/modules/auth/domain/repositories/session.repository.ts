import { Session } from '../entities/session.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

export const ISessionRepository = Symbol('ISessionRepository');

export interface ISessionRepository {
  create(session: Session, tx?: Transaction): Promise<void>;
  findByUserId(userId: number): Promise<Session[]>;
  deleteByUserId(userId: number): Promise<void>;
}
