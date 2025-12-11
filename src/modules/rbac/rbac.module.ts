import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
// Infra Entities
import { RoleOrmEntity } from './infrastructure/persistence/entities/role.orm-entity';
import { PermissionOrmEntity } from './infrastructure/persistence/entities/permission.orm-entity';
import { UserRoleOrmEntity } from './infrastructure/persistence/entities/user-role.orm-entity';
// Repositories
import {
  TypeOrmRoleRepository,
  TypeOrmPermissionRepository,
  TypeOrmUserRoleRepository,
} from './infrastructure/persistence/repositories/typeorm-rbac.repositories';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([
      RoleOrmEntity,
      PermissionOrmEntity,
      UserRoleOrmEntity,
    ]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (c: ConfigService) => ({ ttl: 300, max: 1000 }),
      inject: [ConfigService],
    }),
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
    { provide: 'IRoleRepository', useClass: TypeOrmRoleRepository },
    { provide: 'IPermissionRepository', useClass: TypeOrmPermissionRepository },
    { provide: 'IUserRoleRepository', useClass: TypeOrmUserRoleRepository },
  ],
  exports: [PermissionService, PermissionGuard, RoleService],
})
export class RbacModule {}
