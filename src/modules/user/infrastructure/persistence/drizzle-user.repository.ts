import { Injectable, Inject } from '@nestjs/common';
import { eq, desc, inArray, or } from 'drizzle-orm';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { User } from '../../domain/entities/user.entity';
import { DRIZZLE } from '@database/drizzle.provider';
import * as schema from '@database/schema'; // Import toàn bộ schema cho query builder
import { UserMapper } from './mappers/user.mapper';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class DrizzleUserRepository implements IUserRepository {
  constructor(
    @Inject(DRIZZLE) private readonly db: NodePgDatabase<typeof schema>,
  ) { }

  // --- Helper để lấy DB hoặc Transaction ---
  private getDb(tx?: Transaction) {
    return tx ? (tx as unknown as NodePgDatabase<typeof schema>) : this.db;
  }

  // --- READ METHODS (Dùng Query Builder để join bảng roles) ---

  // 🚀 1. HÀM DÙNG CHO API /api/auth/profile (Cần xem đầy đủ dữ liệu)
  async findById(id: number, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.id, id),
      with: {
        userRoles: { with: { role: true } },
        // ✅ Bật Join bảng HRM
        employeeProfile: {
          with: { location: true, position: { with: { orgUnit: true, jobTitle: true } } },
        },
        // ✅ Bật Join bảng CRM
        organizationProfile: true,
      },
    });
    return UserMapper.toDomain(result);
  }

  // ⚡ 2. HÀM DÙNG ĐỂ LOGIN / XÁC THỰC TOKEN (Phải chạy cực nhanh)
  async findByUsername(username: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
      with: {
        userRoles: { with: { role: true } },
        // ❌ KHÔNG JOIN bảng Employee hay Organization ở đây để tiết kiệm DB
      },
    });
    return UserMapper.toDomain(result);
  }

  async findByEmail(email: string, tx?: Transaction): Promise<User | null> {
    const db = this.getDb(tx);
    const result = await db.query.users.findFirst({
      where: eq(schema.users.email, email),
      with: {
        userRoles: { with: { role: true } },
      },
    });
    return UserMapper.toDomain(result);
  }

  async findByTelegramId(telegramId: string): Promise<User | null> {
    const result = await this.db.query.users.findFirst({
      where: eq(schema.users.telegramId, telegramId),
      with: {
        userRoles: { with: { role: true } },
      },
    });
    return UserMapper.toDomain(result);
  }

  async findAll(): Promise<User[]> {
    const results = await this.db.query.users.findMany({
      orderBy: desc(schema.users.createdAt),
      with: {
        userRoles: { with: { role: true } },
      },
    });
    return results
      .map((u) => UserMapper.toDomain(u))
      .filter((u): u is User => u !== null);
  }

  async findAllActive(): Promise<User[]> {
    const results = await this.db.query.users.findMany({
      where: eq(schema.users.isActive, true),
      with: {
        userRoles: { with: { role: true } },
      },
    });
    return results
      .map((u) => UserMapper.toDomain(u))
      .filter((u): u is User => u !== null);
  }

  // --- WRITE METHODS (Chỉ tác động bảng users) ---

  async save(user: User, tx?: Transaction): Promise<User> {
    const db = this.getDb(tx);
    const data = UserMapper.toPersistence(user);

    // Lưu ý: Hàm này chỉ save thông tin User cơ bản.
    // Việc gán Role (insert vào user_roles) nên được thực hiện bởi 
    // một method khác hoặc service chuyên biệt (VD: AssignRoleService).

    let result;
    if (data.id) {
      // Update
      const res = await db
        .update(schema.users)
        .set(data)
        .where(eq(schema.users.id, data.id))
        .returning();
      result = res[0];
    } else {
      // Insert
      // Loại bỏ ID để DB tự sinh (nếu dùng serial)
      // Nhưng nếu data.id được truyền vào (VD từ register logic), ta giữ lại
      const res = await db
        .insert(schema.users)
        .values(data as typeof schema.users.$inferInsert)
        .returning();
      result = res[0];
    }

    // Return User domain (lúc này chưa có roles vì mới save xong, 
    // trừ khi fetch lại, nhưng để tối ưu ta có thể return user vừa save với roles rỗng hoặc giữ nguyên từ input)
    return UserMapper.toDomain({ ...result, userRoles: [] })!;
  }

  async updateTelegramId(userId: string | number, telegramId: string): Promise<void> {
    await this.db.update(schema.users)
      .set({ telegramId: telegramId })
      .where(eq(schema.users.id, Number(userId)));
  }

  async removeTelegramId(telegramId: string): Promise<void> {
    await this.db.update(schema.users)
      .set({ telegramId: null })
      .where(eq(schema.users.telegramId, telegramId));
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    // Map partial fields manually for update
    const updatePayload: any = {};
    if (data.fullName) updatePayload.fullName = data.fullName;
    if (data.email) updatePayload.email = data.email;
    if (data.isActive !== undefined) updatePayload.isActive = data.isActive;
    updatePayload.updatedAt = new Date();

    const result = await this.db
      .update(schema.users)
      .set(updatePayload)
      .where(eq(schema.users.id, id))
      .returning();

    if (!result[0]) throw new Error('User not found to update');
    return UserMapper.toDomain(result[0])!;
  }

  // 👉 MỚI (SOFT DELETE):
  async delete(id: number, tx?: Transaction): Promise<void> {
    const db = this.getDb(tx);

    // Thay vì dùng db.delete(), ta dùng db.update()
    await db.update(schema.users)
      .set({
        isActive: false,
        deletedAt: new Date(),
        updatedAt: new Date()
      })
      .where(eq(schema.users.id, id));
  }

  async exists(id: number, tx?: Transaction): Promise<boolean> {
    const db = this.getDb(tx);
    // Optimized exist check
    const result = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.id, id))
      .limit(1);
    return result.length > 0;
  }

  async count(): Promise<number> {
    const result = await this.db.execute('SELECT COUNT(*) as count FROM users');
    return Number(result.rows[0].count);
  }

  // ✅ THÊM MỚI: Lấy danh sách user đã tồn tại (chỉ 1 query duy nhất)
  async findExistingUsernamesOrEmails(identifiers: string[], tx?: Transaction) {
    if (!identifiers || identifiers.length === 0) return [];
    const db = this.getDb(tx);
    const results = await db
      .select({ username: schema.users.username, email: schema.users.email })
      .from(schema.users)
      .where(
        or(
          inArray(schema.users.username, identifiers),
          inArray(schema.users.email, identifiers)
        )
      );
    return results;
  }

  // ✅ THÊM MỚI: Bulk Insert (Insert 1 phát 1000 records)
  async saveMany(users: User[], tx?: Transaction): Promise<User[]> {
    if (!users || users.length === 0) return [];
    const db = this.getDb(tx);
    const dataToInsert = users.map(user => {
      const data = UserMapper.toPersistence(user);
      delete (data as any).id; // Bỏ ID để DB tự gen
      return data;
    });

    const results = await db
      .insert(schema.users)
      .values(dataToInsert as typeof schema.users.$inferInsert[])
      .returning();

    return results.map(r => UserMapper.toDomain({ ...r, userRoles: [] })!);
  }
}
