import { Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from '../user/user.module';
import { RbacModule } from '../rbac/rbac.module';
import { DatabaseSeeder } from './seeders/database.seeder';
import { TestController } from './controllers/test.controller';
import { UserOrmEntity } from '../user/infrastructure/persistence/entities/user.orm-entity';
import { RoleOrmEntity } from '../rbac/infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from '../rbac/infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from '../rbac/infrastructure/persistence/entities/user-role.orm-entity';

@Module({
  imports: [
    UserModule,
    RbacModule,
    TypeOrmModule.forFeature([
      UserOrmEntity,
      RoleOrmEntity,
      PermissionOrmEntity,
      UserRoleOrmEntity,
    ]),
  ],
  controllers: [TestController],
  providers: [DatabaseSeeder],
})
export class TestModule implements OnModuleInit {
  constructor(private s: DatabaseSeeder) {}
  async onModuleInit() {
    await this.s.onModuleInit();
  }
}
