import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { User } from '../../user/domain/entities/user.entity';
import { Role } from '../../rbac/domain/entities/role.entity';
import { Permission } from '../../rbac/domain/entities/permission.entity';
import { UserRole } from '../../rbac/domain/entities/user-role.entity';

import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
  ) {}

  async onModuleInit() {
    // Only seed in development
    if (process.env.NODE_ENV !== 'development') {
      return;
    }

    console.log('Seeding database...');

    await this.seedPermissions();
    await this.seedRoles();
    await this.seedUsers();
    await this.assignRolePermissions();
    await this.assignUserRoles();

    console.log('Database seeded successfully!');
  }

  private async seedPermissions(): Promise<void> {
    const permissions = Object.values(SystemPermission).map((name) => {
      const [resource, action] = name.split(':');
      return this.permissionRepository.create({
        name,
        description: `System permission: ${name}`,
        resourceType: resource,
        action: action,
        isActive: true,
        createdAt: new Date(),
      });
    });

    // Save one by one to avoid duplicate errors
    for (const p of permissions) {
      const exists = await this.permissionRepository.findOne({
        where: { name: p.name },
      });
      if (!exists) {
        await this.permissionRepository.save(p);
      }
    }
    console.log(`Checked permissions`);
  }

  private async seedRoles(): Promise<void> {
    const roles = Object.values(SystemRole).map((name) => ({
      name,
      description: `System role: ${name}`,
      isSystem: true,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    }));

    for (const r of roles) {
      const exists = await this.roleRepository.findOne({
        where: { name: r.name },
      });
      if (!exists) {
        await this.roleRepository.save(r);
      }
    }
    console.log(`Checked roles`);
  }

  private async seedUsers(): Promise<void> {
    const users = [
      {
        id: 1001,
        username: 'superadmin',
        email: 'superadmin@example.com',
        hashedPassword: await bcrypt.hash('SuperAdmin123!', 10),
        fullName: 'Super Administrator',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1002,
        username: 'admin',
        email: 'admin@example.com',
        hashedPassword: await bcrypt.hash('Admin123!', 10),
        fullName: 'Administrator',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1003,
        username: 'manager',
        email: 'manager@example.com',
        hashedPassword: await bcrypt.hash('Manager123!', 10),
        fullName: 'Manager User',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1004,
        username: 'staff',
        email: 'staff@example.com',
        hashedPassword: await bcrypt.hash('Staff123!', 10),
        fullName: 'Staff User',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1005,
        username: 'user1',
        email: 'user1@example.com',
        hashedPassword: await bcrypt.hash('User123!', 10),
        fullName: 'Regular User 1',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 1006,
        username: 'user2',
        email: 'user2@example.com',
        hashedPassword: await bcrypt.hash('User123!', 10),
        fullName: 'Regular User 2',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    for (const u of users) {
      const exists = await this.userRepository.findOne({
        where: { username: u.username },
      });
      if (!exists) {
        await this.userRepository.save(u);
      }
    }
    console.log(`Checked users`);
  }

  private async assignRolePermissions(): Promise<void> {
    // Get all permissions
    const permissions = await this.permissionRepository.find();

    // Get all roles
    const roles = await this.roleRepository.find({
      relations: ['permissions'],
    });
    const roleMap = new Map(roles.map((r) => [r.name, r]));

    // SUPER_ADMIN gets all permissions
    const superAdmin = roleMap.get(SystemRole.SUPER_ADMIN);
    if (superAdmin) {
      superAdmin.permissions = permissions;
      await this.roleRepository.save(superAdmin);
    }

    // ADMIN gets most permissions (except system:config)
    const admin = roleMap.get(SystemRole.ADMIN);
    if (admin) {
      admin.permissions = permissions.filter(
        (p) => !p.name.includes('system:'),
      );
      await this.roleRepository.save(admin);
    }

    // MANAGER gets management permissions
    const manager = roleMap.get(SystemRole.MANAGER);
    if (manager) {
      const managerPermissions = permissions.filter(
        (p) =>
          p.name.includes('report:') ||
          p.name.includes('booking:manage') ||
          p.name.includes('user:read'),
      );
      manager.permissions = managerPermissions;
      await this.roleRepository.save(manager);
    }

    // STAFF gets operational permissions
    const staff = roleMap.get(SystemRole.STAFF);
    if (staff) {
      const staffPermissions = permissions.filter(
        (p) =>
          p.name.includes('booking:create') ||
          p.name.includes('booking:read') ||
          p.name.includes('booking:update') ||
          p.name.includes('payment:process'),
      );
      staff.permissions = staffPermissions;
      await this.roleRepository.save(staff);
    }

    // USER gets basic permissions
    const userRole = roleMap.get(SystemRole.USER);
    if (userRole) {
      userRole.permissions = permissions.filter(
        (p) =>
          p.name === SystemPermission.USER_READ ||
          p.name === SystemPermission.BOOKING_CREATE ||
          p.name === SystemPermission.BOOKING_READ ||
          p.name === SystemPermission.PAYMENT_PROCESS,
      );
      await this.roleRepository.save(userRole);
    }

    console.log('Assigned permissions to roles');
  }

  private async assignUserRoles(): Promise<void> {
    const roles = await this.roleRepository.find();
    const roleMap = new Map(roles.map((r) => [r.name, r.id]));

    const assignments = [
      { userId: 1001, roleName: SystemRole.SUPER_ADMIN },
      { userId: 1002, roleName: SystemRole.ADMIN },
      { userId: 1003, roleName: SystemRole.MANAGER },
      { userId: 1004, roleName: SystemRole.STAFF },
      { userId: 1005, roleName: SystemRole.USER },
      { userId: 1006, roleName: SystemRole.USER },
    ];

    for (const assignment of assignments) {
      const roleId = roleMap.get(assignment.roleName);
      if (roleId) {
        const exists = await this.userRoleRepository.findOne({
          where: { userId: assignment.userId, roleId },
        });
        if (!exists) {
          await this.userRoleRepository.save({
            userId: assignment.userId,
            roleId,
            assignedBy: 1001, // superadmin
            assignedAt: new Date(),
          });
        }
      }
    }

    console.log('Assigned roles to users');
  }
}
