import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema'; // Sẽ tự động lấy từ index.ts mới
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  private readonly logger = new Logger(DatabaseSeeder.name);

  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) { }

  async onModuleInit() {
    // Chỉ chạy khi biến môi trường cho phép hoặc ở môi trường dev
    if (process.env.RUN_SEEDS !== 'true' && process.env.NODE_ENV !== 'development') {
      return;
    }

    this.logger.log('🌱 Bắt đầu Seeding database (New Schema: Identity & Profile)...');

    try {
      // 1. Seed cấu hình hệ thống
      await this.seedPermissions();
      await this.seedRoles();

      // 2. Seed dữ liệu từ điển HRM (Phòng ban, Chức danh)
      await this.seedHrmDictionaries();

      // 3. Seed Users & Employee Profiles
      await this.seedUsersAndProfiles();

      // 4. Gán quyền
      await this.assignPermissionsToRoles();
      await this.assignRolesToUsers();

      this.logger.log('✅ Database seeded successfully!');
    } catch (error) {
      this.logger.error('❌ Seeding failed:', error);
    }
  }

  private async seedPermissions() {
    const values = Object.values(SystemPermission).map((name) => {
      const [res, act] = name.split(':');
      return {
        name,
        resourceType: res,
        action: act,
        isActive: true,
        description: `System permission: ${name}`,
      };
    });

    if (values.length > 0) {
      await this.db
        .insert(schema.permissions)
        .values(values)
        .onConflictDoNothing({ target: schema.permissions.name });
    }
    this.logger.log(` - Checked/Inserted ${values.length} permissions`);
  }

  private async seedRoles() {
    const values = Object.values(SystemRole).map((name) => ({
      name,
      description: `System role: ${name}`,
      isSystem: true,
      isActive: true,
    }));

    if (values.length > 0) {
      await this.db
        .insert(schema.roles)
        .values(values)
        .onConflictDoNothing({ target: schema.roles.name });
    }
    this.logger.log(` - Checked/Inserted ${values.length} roles`);
  }

  // ✅ BƯỚC MỚI: Tạo dữ liệu mồi cho Cơ cấu tổ chức
  private async seedHrmDictionaries() {
    // Tạo 1 phòng ban gốc (Công ty)
    await this.db.insert(schema.orgUnits)
      .values({ type: 'COMPANY', code: 'HQ', name: 'Trụ sở chính Công ty' })
      .onConflictDoNothing({ target: schema.orgUnits.code });

    // Tạo 1 vài chức danh cơ bản
    const titles = [{ name: 'Tổng Giám Đốc' }, { name: 'Trưởng Phòng' }, { name: 'Nhân viên' }];
    await this.db.insert(schema.jobTitles)
      .values(titles)
      .onConflictDoNothing({ target: schema.jobTitles.name });

    this.logger.log(' - HRM Dictionaries checked/inserted');
  }

  // ✅ BƯỚC ĐÃ REFACTOR: Tách biệt việc tạo User và Employee Profile
  private async seedUsersAndProfiles() {
    const hashedPassword = await bcrypt.hash('123456', 10);

    const usersToSeed = [
      { username: 'superadmin', email: 'admin@test.com', employeeCode: 'ADMIN-001', fullName: 'Super Admin' },
      { username: 'user1', email: 'user@test.com', employeeCode: 'NV-0001', fullName: 'Normal User' },
    ];

    for (const data of usersToSeed) {
      // 1. Kiểm tra xem user Identity đã tồn tại chưa
      const existingUser = await this.db.query.users.findFirst({
        where: eq(schema.users.username, data.username),
      });

      if (!existingUser) {
        // 2. Insert Identity vào bảng `users`
        const [newUser] = await this.db
          .insert(schema.users)
          .values({
            username: data.username,
            email: data.email,
            hashedPassword: hashedPassword,
            isActive: true,
          })
          .returning({ id: schema.users.id }); // Lấy ID vừa tạo

        // 3. Insert Profile vào bảng `employees` sử dụng ID vừa lấy
        await this.db
          .insert(schema.employees)
          .values({
            userId: newUser.id,
            employeeCode: data.employeeCode,
            fullName: data.fullName,
            // orgUnitId, jobTitleId có thể để null trong lúc seed ban đầu
          });

        this.logger.log(` - Created User Identity & Employee Profile for: ${data.username}`);
      }
    }
  }

  private async assignPermissionsToRoles() {
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });

    if (!adminRole) return;

    const allPerms = await this.db.select({ id: schema.permissions.id }).from(schema.permissions);
    if (allPerms.length === 0) return;

    const rolePermissionsValues = allPerms.map((perm) => ({
      roleId: adminRole.id,
      permissionId: perm.id,
    }));

    await this.db
      .insert(schema.rolePermissions)
      .values(rolePermissionsValues)
      .onConflictDoNothing();

    this.logger.log(` - Assigned ${allPerms.length} permissions to Super Admin`);
  }

  private async assignRolesToUsers() {
    const [adminUser, adminRole] = await Promise.all([
      this.db.query.users.findFirst({
        where: eq(schema.users.username, 'superadmin'),
        columns: { id: true },
      }),
      this.db.query.roles.findFirst({
        where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
        columns: { id: true },
      }),
    ]);

    if (adminUser && adminRole) {
      await this.db
        .insert(schema.userRoles)
        .values({
          userId: adminUser.id,
          roleId: adminRole.id,
        })
        .onConflictDoNothing();

      this.logger.log(' - Assigned Super Admin role to user: superadmin');
    }
  }
}
