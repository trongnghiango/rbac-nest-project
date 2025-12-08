import { Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module';

import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';

import { User } from '../user/domain/entities/user.entity';
import { Role } from '../rbac/domain/entities/role.entity';
import { Permission } from '../rbac/domain/entities/permission.entity';
import { UserRole } from '../rbac/domain/entities/user-role.entity';

@Module({
  imports: [
    UserModule,
    RbacModule,
    TypeOrmModule.forFeature([User, Role, Permission, UserRole]),
  ],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule implements OnModuleInit {
  constructor(private databaseSeeder: DatabaseSeeder) {}

  async onModuleInit() {
    // Auto-seed on module initialization
    await this.databaseSeeder.onModuleInit();
  }
}
