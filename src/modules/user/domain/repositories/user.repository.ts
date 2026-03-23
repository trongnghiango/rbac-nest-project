import { User } from '../entities/user.entity';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

// 1. Token (Runtime)
export const IUserRepository = Symbol('IUserRepository');

// 2. Interface (Compile-time)
export interface IUserRepository {
  findById(id: number, tx?: Transaction): Promise<User | null>;
  findByUsername(username: string, tx?: Transaction): Promise<User | null>;
  findByEmail(email: string, tx?: Transaction): Promise<User | null>;

  findByTelegramId(telegramId: string): Promise<User | null>;
  updateTelegramId(userId: string | number, telegramId: string): Promise<void>;
  removeTelegramId(telegramId: string): Promise<void>;

  findAllActive(): Promise<User[]>;
  findAll(): Promise<User[]>;

  save(user: User, tx?: Transaction): Promise<User>;
  update(id: number, data: Partial<User>): Promise<User>;
  delete(id: number, tx?: Transaction): Promise<void>;
  exists(id: number, tx?: Transaction): Promise<boolean>;
  count(): Promise<number>;

  //
  findExistingUsernamesOrEmails(identifiers: string[], tx?: Transaction): Promise<{ username: string; email: string | null }[]>;
  saveMany(users: User[], tx?: Transaction): Promise<User[]>;
}
