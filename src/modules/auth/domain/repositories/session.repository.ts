import { Session } from '../entities/session.entity';

export const ISessionRepository = Symbol('ISessionRepository');

export interface ISessionRepository {
  create(session: Session): Promise<void>;
  findByUserId(userId: number): Promise<Session[]>;
  deleteByUserId(userId: number): Promise<void>;

  findByRefreshToken(refreshToken: string): Promise<Session | null>;
  update(id: string, data: Partial<Session>): Promise<void>;

  // 👉 THÊM tinh nang thu hoi Token - MỚI
  findByToken(token: string): Promise<Session | null>;
  deleteByToken(token: string): Promise<void>;
}
