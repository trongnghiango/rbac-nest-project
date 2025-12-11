import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { UserModule } from '../user/user.module';

import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
import { RoleController } from './infrastructure/controllers/role.controller';

import { Role } from './domain/entities/role.entity';
import { Permission } from './domain/entities/permission.entity';
import { UserRole } from './domain/entities/user-role.entity';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { RbacManagerService } from './application/services/rbac-manager.service';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([Role, Permission, UserRole]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        ttl: configService.get('RBAC_CACHE_TTL', 300),
        max: configService.get('RBAC_CACHE_MAX', 1000),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService,
    RoleService,
    PermissionGuard,
    RbacManagerService,
  ],
  exports: [PermissionService, PermissionGuard, RoleService],
})
export class RbacModule {}
