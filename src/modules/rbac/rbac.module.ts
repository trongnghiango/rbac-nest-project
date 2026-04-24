import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
import {
  DrizzleRoleRepository,
  DrizzlePermissionRepository,
  DrizzleUserRoleRepository,
} from './infrastructure/persistence/repositories/drizzle-rbac.repositories';
import {
  IRoleRepository,
  IPermissionRepository,
  IUserRoleRepository,
} from './domain/repositories/rbac.repository';
import { IRbacManageService } from './domain/ports/rbac-manage.service.port';
import { RbacManageService } from './application/services/rbac-manage.service';

@Module({
  imports: [
    // Không cần import CacheModule nữa vì RedisCacheModule là Global
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
    { provide: IRbacManageService, useClass: RbacManageService },
    { provide: IRoleRepository, useClass: DrizzleRoleRepository },
    { provide: IPermissionRepository, useClass: DrizzlePermissionRepository },
    { provide: IUserRoleRepository, useClass: DrizzleUserRoleRepository },
  ],
  exports: [
    PermissionService,
    PermissionGuard,
    RoleService,
    IRoleRepository,
    IUserRoleRepository,
    RbacManagerService,
    IRbacManageService,
  ],
})
export class RbacModule { }
