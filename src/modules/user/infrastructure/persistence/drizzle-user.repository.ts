import { Injectable } from '@nestjs/common';
import { eq, desc } from 'drizzle-orm';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { DrizzleBaseRepository } from '@core/shared/infrastructure/persistence/drizzle-base.repository';
import { users } from '@database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository
  extends DrizzleBaseRepository
  implements IUserRepository
{
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.id, id));
    return UserMapper.toDomain(result[0]);
  }

  async findByUsername(
    username: string,
    tx?: Transaction,
  ): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db
      .select()
      .from(users)
      .where(eq(users.username, username));
    return UserMapper.toDomain(result[0]);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.select().from(users).where(eq(users.email, email));
    return UserMapper.toDomain(result[0]);
  }

  async findAllActive(): Promise<User[]> {
    const result = await this.db
      .select()
      .from(users)
      .where(eq(users.isActive, true));
    return result
      .map((u) => UserMapper.toDomain(u))
      .filter((u): u is User => u !== null);
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);
    let result;

    if (data.id) {
      result = await db
        .update(users)
        .set(data)
        .where(eq(users.id, data.id))
        .returning();
    } else {
      const { id, ...insertData } = data;
      result = await db
        .insert(users)
        .values(insertData as typeof users.$inferInsert)
        .returning();
    }
    return UserMapper.toDomain(result[0])!;
  }

  // ✅ ĐÃ IMPLEMENT ĐÀNG HOÀNG
  async findAll(): Promise<User[]> {
    const results = await this.db
      .select()
      .from(users)
      .orderBy(desc(users.createdAt));
    return results
      .map((u) => UserMapper.toDomain(u))
      .filter((u): u is User => u !== null);
  }

  // ✅ ĐÃ IMPLEMENT ĐÀNG HOÀNG (Thay vì throw Error)
  async update(id: number, data: Partial<User>): Promise<User> {
    // Lưu ý: data ở đây là Partial<User> (Domain Entity),
    // nên convert sang Persistence Model là việc khó nếu không có full object.
    // Tuy nhiên, nếu chỉ update vài trường simple, ta có thể map thủ công hoặc dùng save().
    // Ở đây tôi implement update trực tiếp vào DB các trường có thể map được.

    // Cách an toàn nhất theo DDD: Load -> Modify -> Save.
    // Nhưng vì Interface yêu cầu update(id, data), ta làm như sau:

    // 1. Map các field update sang DB schema format
    const updatePayload: any = {};
    if (data.fullName) updatePayload.fullName = data.fullName;
    if (data.email) updatePayload.email = data.email;
    if (data.isActive !== undefined) updatePayload.isActive = data.isActive;
    updatePayload.updatedAt = new Date();

    const result = await this.db
      .update(users)
      .set(updatePayload)
      .where(eq(users.id, id))
      .returning();

    if (!result[0]) throw new Error('User not found to update');
    return UserMapper.toDomain(result[0])!;
  }

  async delete(id: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    await db.delete(users).where(eq(users.id, id));
  }

  async exists(id: number, tx?: Transaction): Promise<boolean> {
    const u = await this.findById(id, tx);
    return !!u;
  }

  async count(): Promise<number> {
    const result = await this.db.execute('SELECT COUNT(*) as count FROM users'); // Raw query cho nhanh hoặc dùng count() của drizzle mới
    return Number(result.rows[0].count);
  }
}
