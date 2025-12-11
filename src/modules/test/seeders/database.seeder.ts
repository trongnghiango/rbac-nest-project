import { Injectable, OnModuleInit, Inject } from '@nestjs/common';
import { DRIZZLE } from '../../../database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '../../../database/schema';
import { eq } from 'drizzle-orm';
import * as bcrypt from 'bcrypt';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(@Inject(DRIZZLE) private db: NodePgDatabase<typeof schema>) {}

  async onModuleInit() {
    if (process.env.NODE_ENV !== 'development') return;
    console.log('🌱 Seeding database (Drizzle)...');

    await this.seedPermissions();
    await this.seedRoles();
    await this.seedUsers();
    await this.assignPermissionsToRoles();
    await this.assignRolesToUsers();

    console.log('✅ Database seeded successfully!');
  }

  private async seedPermissions() {
    for (const name of Object.values(SystemPermission)) {
      const [res, act] = name.split(':');
      const exists = await this.db.query.permissions.findFirst({
        where: eq(schema.permissions.name, name),
      });
      if (!exists) {
        await this.db.insert(schema.permissions).values({
          name,
          resourceType: res,
          action: act,
          isActive: true,
          description: `System permission: ${name}`,
        });
      }
    }
    console.log(' - Permissions checked');
  }

  private async seedRoles() {
    for (const name of Object.values(SystemRole)) {
      const exists = await this.db.query.roles.findFirst({
        where: eq(schema.roles.name, name),
      });
      if (!exists) {
        await this.db.insert(schema.roles).values({
          name,
          description: `System role: ${name}`,
          isSystem: true,
          isActive: true,
        });
      }
    }
    console.log(' - Roles checked');
  }

  private async seedUsers() {
    const password = await bcrypt.hash('123456', 10);
    const users = [
      {
        username: 'superadmin',
        fullName: 'Super Admin',
        email: 'admin@test.com',
      },
      { username: 'user1', fullName: 'Normal User', email: 'user@test.com' },
    ];

    for (const u of users) {
      const exists = await this.db.query.users.findFirst({
        where: eq(schema.users.username, u.username),
      });
      if (!exists) {
        await this.db.insert(schema.users).values({
          ...u,
          hashedPassword: password,
          isActive: true,
        });
      }
    }
    console.log(' - Users checked');
  }

  private async assignPermissionsToRoles() {
    // 1. Get Admin Role
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });
    if (!adminRole) return;

    // 2. Get All Permissions
    const allPerms = await this.db.select().from(schema.permissions);

    // 3. Insert into role_permissions (Ignore duplicates)
    for (const perm of allPerms) {
      await this.db
        .insert(schema.rolePermissions)
        .values({ roleId: adminRole.id, permissionId: perm.id })
        .onConflictDoNothing()
        .catch(() => {}); // Catch duplicate key error silently
    }
    console.log(' - Admin permissions assigned');
  }

  private async assignRolesToUsers() {
    const adminUser = await this.db.query.users.findFirst({
      where: eq(schema.users.username, 'superadmin'),
    });
    const adminRole = await this.db.query.roles.findFirst({
      where: eq(schema.roles.name, SystemRole.SUPER_ADMIN),
    });

    if (adminUser && adminRole) {
      await this.db
        .insert(schema.userRoles)
        .values({ userId: adminUser.id, roleId: adminRole.id })
        .onConflictDoNothing();
    }
    console.log(' - Admin role assigned');
  }
}
