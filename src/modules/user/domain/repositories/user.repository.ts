import { User } from '../entities/user.entity';

// 1. Token (Runtime)
export const IUserRepository = Symbol('IUserRepository');

// 2. Interface (Compile-time)
export interface IUserRepository {
  findById(id: number): Promise<User | null>;
  findByUsername(username: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;

  findByTelegramId(telegramId: string): Promise<User | null>;
  updateTelegramId(userId: string | number, telegramId: string): Promise<void>;
  removeTelegramId(telegramId: string): Promise<void>;

  findAllActive(): Promise<User[]>;
  findAll(): Promise<User[]>;

  save(user: User): Promise<User>;
  delete(id: number): Promise<void>;
  exists(id: number): Promise<boolean>;
  count(): Promise<number>;

  //
  findExistingUsernamesOrEmails(identifiers: string[]): Promise<{ username: string; email: string | null }[]>;
  saveMany(users: User[]): Promise<User[]>;
}
