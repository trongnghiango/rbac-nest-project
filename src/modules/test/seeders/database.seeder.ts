import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import { CORE_ROLES } from '../../rbac/domain/constants/rbac.constants'; // ✅ Import hằng số mới

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  private readonly logger = new Logger(DatabaseSeeder.name);

  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) { }

  async onModuleInit() {
    if (process.env.RUN_SEEDS !== 'true'
      // && process.env.NODE_ENV !== 'development'
    ) {
      return;
    }

    this.logger.log('🌱 Bắt đầu Seeding database (Dynamic RBAC)...');

    try {
      // 1. Chỉ tạo Role hệ thống (SUPER_ADMIN)
      await this.seedCoreRoles();

      // 2. Tạo Master Permission (manage:all)
      await this.seedMasterPermission();

      // 3. Seed dữ liệu từ điển HRM (Phòng ban, Chức danh)
      await this.seedHrmDictionaries();

      // 4. Seed User Admin gốc
      await this.seedUsersAndProfiles();

      // 5. Gán quyền tối cao cho Admin gốc
      await this.assignRolesToUsers();

      this.logger.log('✅ Database seeded successfully!');
    } catch (error) {
      this.logger.error('❌ Seeding failed:', error);
    }
  }

  private async seedCoreRoles() {
    // Chỉ tạo đúng Role cốt lõi. Các Role khác (MANAGER, STAFF) sẽ do file rbac.csv sinh ra.
    await this.db
      .insert(schema.roles)
      .values({
        name: CORE_ROLES.SUPER_ADMIN,
        description: 'System role: Root Administrator',
        isSystem: true,
        isActive: true,
      })
      .onConflictDoNothing({ target: schema.roles.name });
    this.logger.log(' - Seeded CORE_ROLES');
  }

  private async seedMasterPermission() {
    // Tạo 1 permission vạn năng để mồi
    await this.db
      .insert(schema.permissions)
      .values({
        name: 'manage:all',
        resourceType: '*',
        action: '*',
        isActive: true,
        description: 'Master Permission',
      })
      .onConflictDoNothing({ target: schema.permissions.name });
  }

  private async seedHrmDictionaries() {
    await this.db.insert(schema.orgUnits)
      .values({ type: 'COMPANY', code: 'HQ', name: 'Trụ sở chính Công ty' })
      .onConflictDoNothing({ target: schema.orgUnits.code });

    const titles = [{ name: 'Tổng Giám Đốc' }, { name: 'Trưởng Phòng' }, { name: 'Nhân viên' }];
    await this.db.insert(schema.jobTitles)
      .values(titles)
      .onConflictDoNothing({ target: schema.jobTitles.name });

    this.logger.log(' - HRM Dictionaries seeded');
  }

  private async seedUsersAndProfiles() {
    const hashedPassword = await bcrypt.hash('123456', 10);
    const existingUser = await this.db.query.users.findFirst({
      where: eq(schema.users.username, 'superadmin'),
    });

    if (!existingUser) {
      const [newUser] = await this.db
        .insert(schema.users)
        .values({
          username: 'superadmin',
          email: 'admin@test.com',
          hashedPassword: hashedPassword,
          isActive: true,
        })
        .returning({ id: schema.users.id });

      await this.db
        .insert(schema.employees)
        .values({
          userId: newUser.id,
          employeeCode: 'ADMIN-001',
          fullName: 'Super Admin',
        });

      this.logger.log(' - Created Master User: superadmin');
    }
  }

  private async assignRolesToUsers() {
    const [adminUser, adminRole] = await Promise.all([
      this.db.query.users.findFirst({
        where: eq(schema.users.username, 'superadmin'),
        columns: { id: true },
      }),
      this.db.query.roles.findFirst({
        where: eq(schema.roles.name, CORE_ROLES.SUPER_ADMIN),
        columns: { id: true },
      }),
    ]);

    if (adminUser && adminRole) {
      await this.db
        .insert(schema.userRoles)
        .values({ userId: adminUser.id, roleId: adminRole.id })
        .onConflictDoNothing();

      this.logger.log(' - Assigned SUPER_ADMIN role to superadmin');
    }
  }
}