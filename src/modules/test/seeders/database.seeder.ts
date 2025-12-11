import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserOrmEntity } from '../../user/infrastructure/persistence/entities/user.orm-entity';
import { RoleOrmEntity } from '../../rbac/infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from '../../rbac/infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../../rbac/infrastructure/persistence/entities/user-role.orm-entity';
import {
  SystemPermission,
  SystemRole,
} from '../../rbac/domain/constants/rbac.constants';

@Injectable()
export class DatabaseSeeder implements OnModuleInit {
  constructor(
    @InjectRepository(UserOrmEntity) private uRepo: Repository<UserOrmEntity>,
    @InjectRepository(RoleOrmEntity) private rRepo: Repository<RoleOrmEntity>,
    @InjectRepository(PermissionOrmEntity)
    private pRepo: Repository<PermissionOrmEntity>,
    @InjectRepository(UserRoleOrmEntity)
    private urRepo: Repository<UserRoleOrmEntity>,
  ) {}

  async onModuleInit() {
    if (process.env.NODE_ENV !== 'development') return;
    console.log('Seeding...');
    await this.seedPerms();
    await this.seedRoles();
    await this.seedUsers();
    await this.assign();
    console.log('Seeded.');
  }

  async seedPerms() {
    for (const name of Object.values(SystemPermission)) {
      const [res, act] = name.split(':');
      if (!(await this.pRepo.findOne({ where: { name } }))) {
        await this.pRepo.save(
          this.pRepo.create({
            name,
            resourceType: res,
            action: act,
            isActive: true,
          }),
        );
      }
    }
  }

  async seedRoles() {
    for (const name of Object.values(SystemRole)) {
      if (!(await this.rRepo.findOne({ where: { name } }))) {
        await this.rRepo.save(
          this.rRepo.create({ name, isSystem: true, isActive: true }),
        );
      }
    }
  }

  async seedUsers() {
    const pw = await bcrypt.hash('123456', 10);
    const users = [
      {
        username: 'superadmin',
        fullName: 'Super Admin',
        email: 'admin@test.com',
      },
      { username: 'user1', fullName: 'Normal User', email: 'user@test.com' },
    ];
    for (const u of users) {
      if (!(await this.uRepo.findOne({ where: { username: u.username } }))) {
        await this.uRepo.save(
          this.uRepo.create({
            ...u,
            hashedPassword: pw,
            isActive: true,
            createdAt: new Date(),
          }),
        );
      }
    }
  }

  async assign() {
    const adminRole = await this.rRepo.findOne({
      where: { name: SystemRole.SUPER_ADMIN },
      relations: ['permissions'],
    });
    if (!adminRole) return;

    // Assign all perms to superadmin
    const allPerms = await this.pRepo.find();
    adminRole.permissions = allPerms;
    await this.rRepo.save(adminRole);

    const adminUser = await this.uRepo.findOne({
      where: { username: 'superadmin' },
    });
    if (adminUser) {
      const ur = await this.urRepo.findOne({
        where: { userId: adminUser.id, roleId: adminRole.id },
      });
      if (!ur)
        await this.urRepo.save({
          userId: adminUser.id,
          roleId: adminRole.id,
          assignedAt: new Date(),
        });
    }
  }
}
