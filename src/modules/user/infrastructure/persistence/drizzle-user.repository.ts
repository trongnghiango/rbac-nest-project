import { Injectable, Inject } from '@nestjs/common';
import { eq, desc, inArray, or, sql } from 'drizzle-orm';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema';
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository implements IUserRepository {
  constructor(
    @Inject(DRIZZLE) private readonly db: NodePgDatabase<typeof schema>,
  ) { }

  private getDb(tx?: Transaction) {
    return tx ? (tx as unknown as NodePgDatabase<typeof schema>) : this.db;
  }

  // 🚀 1. Lấy đầy đủ nhất (Dùng cho Profile/Auth)
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.id, id),
      with: {
        metadata: true, // ✅ Lấy thông tin cá nhân
        userRoles: { with: { role: true } },
        employeeProfile: {
          with: {
            location: true,
            position: { with: { orgUnit: true, jobTitle: true } }
          },
        },
        organizationProfile: true,
      },
    });
    return UserMapper.toDomain(result);
  }

  // ⚡ 2. Tìm nhanh (Dùng cho Login)
  async findByUsername(username: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
      with: {
        metadata: true, // Luôn lấy metadata cơ bản
        userRoles: { with: { role: true } },
      },
    });
    return UserMapper.toDomain(result);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.email, email),
      with: {
        metadata: true,
        userRoles: { with: { role: true } },
      },
    });
    return UserMapper.toDomain(result);
  }

  async findByTelegramId(telegramId: string): Promise<User | null> {
    const result = await this.db.query.users.findFirst({
      where: eq(schema.users.telegramId, telegramId),
      with: {
        metadata: true,
        userRoles: { with: { role: true } },
      },
    });
    return UserMapper.toDomain(result);
  }

  async findAll(): Promise<User[]> {
    const results = await this.db.query.users.findMany({
      orderBy: desc(schema.users.createdAt),
      with: {
        metadata: true,
        userRoles: { with: { role: true } },
      },
    });
    return results
      .map((u) => UserMapper.toDomain(u))
      .filter((u): u is User => u !== null);
  }

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);

    let result;
    if (data.id) {
      const res = await db.update(schema.users)
        .set(data)
        .where(eq(schema.users.id, data.id))
        .returning();
      result = res[0];
    } else {
      const res = await db.insert(schema.users)
        .values(data as typeof schema.users.$inferInsert)
        .returning();
      result = res[0];
    }

    // Sau khi save user core, ta return domain (chưa join metadata nhưng giữ data hiện có)
    return UserMapper.toDomain({ ...result, userRoles: [] })!;
  }

  // ✅ Các phương thức khác giữ nguyên logic cũ nhưng cập nhật query nếu cần...

  async delete(id: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);
    await db.update(schema.users)
      .set({ isActive: false, deletedAt: new Date() })
      .where(eq(schema.users.id, id));
  }

  async findExistingUsernamesOrEmails(identifiers: string[], tx?: Transaction) {
    if (!identifiers || identifiers.length === 0) return [];
    const db = this.getDb(tx);
    return await db.select({ username: schema.users.username, email: schema.users.email })
      .from(schema.users)
      .where(or(
        inArray(schema.users.username, identifiers),
        inArray(schema.users.email, identifiers)
      ));
  }

  async saveMany(users: User[], tx?: Transaction): Promise<User[]> {
    if (!users || users.length === 0) return [];
    const db = this.getDb(tx);
    const dataToInsert = users.map(user => {
      const data = UserMapper.toPersistence(user);
      delete (data as any).id;
      return data;
    });

    const results = await db.insert(schema.users).values(dataToInsert).returning();
    return results.map(r => UserMapper.toDomain({ ...r, userRoles: [] })!);
  }

  async findAllActive(): Promise<User[]> {
    const results = await this.db.query.users.findMany({
      where: eq(schema.users.isActive, true),
      with: {
        metadata: true,
        userRoles: { with: { role: true } },
      },
    });
    return results.map(u => UserMapper.toDomain(u)).filter((u): u is User => u !== null);
  }

  // ✅ Thêm hàm này
  async updateTelegramId(userId: string | number, telegramId: string): Promise<void> {
    await this.db.update(schema.users)
      .set({ telegramId })
      .where(eq(schema.users.id, Number(userId)));
  }

  // ✅ Thêm hàm này
  async removeTelegramId(telegramId: string): Promise<void> {
    await this.db.update(schema.users)
      .set({ telegramId: null })
      .where(eq(schema.users.telegramId, telegramId));
  }

  // ✅ Thêm hàm này
  async count(): Promise<number> {
    const result = await this.db.execute(sql`SELECT COUNT(*) as count FROM users`);
    return Number((result.rows[0] as any).count);
  }

  // ✅ Thêm hàm update (Dùng cho logic UserService)
  async update(id: number, data: Partial<User>): Promise<User> {
    const updatePayload: any = {};
    if (data.username) updatePayload.username = data.username;
    if (data.isActive !== undefined) updatePayload.isActive = data.isActive;
    // ... map các trường khác nếu cần

    const result = await this.db.update(schema.users)
      .set({ ...updatePayload, updatedAt: new Date() })
      .where(eq(schema.users.id, id))
      .returning();

    // Re-fetch để có đầy đủ relations sau khi update
    return this.findById(id) as Promise<User>;
  }

  async exists(id: number, tx?: Transaction): Promise<boolean> {
    const db = this.getDb(tx);
    const result = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.id, id))
      .limit(1);
    return result.length > 0;
  }
}
