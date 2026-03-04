import { Injectable, OnModuleInit, Inject, Logger } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  private readonly logger = new Logger(DatabaseSeeder.name);

  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async onModuleInit() {
    // Chỉ chạy khi biến môi trường cho phép hoặc ở môi trường dev
    if (process.env.RUN_SEEDS !== 'true' && process.env.NODE_ENV !== 'development') {
      return;
    }

    this.logger.log('🌱 Seeding database (Drizzle)...');
    
    try {
      await this.seedPermissions();
      await this.seedRoles();
      await this.seedUsers();
      await this.assignPermissionsToRoles(); // Gán quyền cho Admin
      await this.assignRolesToUsers();       // Gán role Admin cho user
      
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
      // Bulk Insert + Bỏ qua nếu trùng tên (yêu cầu cột 'name' phải là unique trong schema)
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

  private async seedUsers() {
    const hashedPassword = await bcrypt.hash('123456', 10);
    const usersData = [
      {
        username: 'superadmin',
        fullName: 'Super Admin',
        email: 'admin@test.com',
        hashedPassword,
        isActive: true,
      },
      {
        username: 'user1',
        fullName: 'Normal User',
        email: 'user@test.com',
        hashedPassword,
        isActive: true,
      },
    ];

    await this.db
      .insert(schema.users)
      .values(usersData)
      .onConflictDoNothing({ target: schema.users.username }); // Yêu cầu username unique

    this.logger.log(' - Users checked/inserted');
  }

  private async assignPermissionsToRoles() {
    // 1. Lấy Admin Role
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });

    if (!adminRole) {
      this.logger.warn('⚠️ Super Admin role not found, skipping permission assignment.');
      return;
    }

    // 2. Lấy tất cả permissions hiện có trong DB
    const allPerms = await this.db.select({ id: schema.permissions.id }).from(schema.permissions);

    if (allPerms.length === 0) return;

    // 3. Chuẩn bị data mapping
    const rolePermissionsValues = allPerms.map((perm) => ({
      roleId: adminRole.id,
      permissionId: perm.id,
    }));

    // 4. Bulk Insert vào bảng trung gian
    // Lưu ý: onConflictDoNothing ở đây cần composite unique key (role_id + permission_id) trong schema
    await this.db
      .insert(schema.rolePermissions)
      .values(rolePermissionsValues)
      .onConflictDoNothing();

    this.logger.log(` - Assigned ${allPerms.length} permissions to Super Admin`);
  }

  private async assignRolesToUsers() {
    // Cách query tối ưu: Lấy cả 2 ID cùng lúc nếu có thể, hoặc query song song
    const [adminUser, adminRole] = await Promise.all([
      this.db.query.users.findFirst({
        where: eq(schema.users.username, 'superadmin'),
        columns: { id: true }, // Chỉ lấy ID cho nhẹ
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
        .onConflictDoNothing(); // Cần unique constraint (userId, roleId)
      
      this.logger.log(' - Assigned Super Admin role to user: superadmin');
    }
  }
}
