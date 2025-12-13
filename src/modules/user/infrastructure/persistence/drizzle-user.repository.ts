import { Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { IUserRepository } from '../../domain/repositories/user-repository.interface';
import { User } from '../../domain/entities/user.entity';
import { DrizzleBaseRepository } from '../../../../core/shared/infrastructure/persistence/drizzle-base.repository';
import { users } from '../../../../database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '../../../../core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository extends DrizzleBaseRepository implements IUserRepository {
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.id, id));
    return UserMapper.toDomain(result[0]);
  }

  async findByUsername(username: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.username, username));
    return UserMapper.toDomain(result[0]);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.email, email));
    return UserMapper.toDomain(result[0]);
  }

  async findAllActive(): Promise<User[]> {
    const result = await this.db.select().from(users).where(eq(users.isActive, true));
    return result.map(u => UserMapper.toDomain(u)!);
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);
    let result;

    if (data.id) {
        result = await db.update(users)
            .set(data)
            .where(eq(users.id, data.id))
            .returning();
    } else {
        const { id, ...insertData } = data;
        // FIX: Cast explicitly to Insert Type
        result = await db.insert(users)
            .values(insertData as typeof users.$inferInsert)
            .returning();
    }
    return UserMapper.toDomain(result[0])!;
  }

  async findAll(): Promise<User[]> { return []; }
  async update(): Promise<User> { throw new Error('Use save instead'); }
  async delete(id: number, tx?: Transaction): Promise<void> {
      const db = this.getDb(tx);
      await db.delete(users).where(eq(users.id, id));
  }
  async exists(id: number, tx?: Transaction): Promise<boolean> {
      const u = await this.findById(id, tx);
      return !!u;
  }
  async count(): Promise<number> { return 0; }
}
