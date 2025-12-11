import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
// Drizzle Repositories
import {
  DrizzleRoleRepository,
  DrizzlePermissionRepository,
  DrizzleUserRoleRepository,
} from './infrastructure/persistence/repositories/drizzle-rbac.repositories';

@Module({
  imports: [
    UserModule,
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
    { provide: 'IRoleRepository', useClass: DrizzleRoleRepository },
    { provide: 'IPermissionRepository', useClass: DrizzlePermissionRepository },
    { provide: 'IUserRoleRepository', useClass: DrizzleUserRoleRepository },
  ],
  exports: [PermissionService, PermissionGuard, RoleService],
})
export class RbacModule {}
