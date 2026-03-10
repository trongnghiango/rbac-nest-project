#!/bin/bash

# Màu sắc cho log
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

log "🚀 STARTING REDIS CACHE REFACTORING (V2 - Custom ENV)..."

# 1. Cài đặt thư viện Redis
log "📦 Installing Redis dependencies..."
npm install cache-manager-redis-store@2
npm install --save-dev @types/cache-manager-redis-store

# 2. Tạo file Config cho Redis (Map với .env của bạn)
log "⚙️ Creating Redis Config..."
# Lưu ý: Chúng ta map RBAC_CACHE_TTL vào ttl chung của Redis
cat > src/config/redis.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  // Sử dụng biến RBAC_CACHE_TTL từ .env của bạn
  ttl: parseInt(process.env.RBAC_CACHE_TTL || '300', 10),
  max: parseInt(process.env.RBAC_CACHE_MAX || '1000', 10),
}));
EOF

# 3. Định nghĩa Port (Interface) cho Cache Service trong Core
log "🔌 Creating Cache Port (Interface)..."
mkdir -p src/core/shared/application/ports
cat > src/core/shared/application/ports/cache.port.ts << 'EOF'
// Token để Inject
export const ICacheService = Symbol('ICacheService');

// Interface trừu tượng
export interface ICacheService {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  reset(): Promise<void>;
}
EOF

# 4. Tạo Infrastructure Implementation (Redis Adapter)
log "🏗️ Creating Redis Infrastructure Adapter..."
mkdir -p src/core/shared/infrastructure/cache
cat > src/core/shared/infrastructure/cache/redis-cache.adapter.ts << 'EOF'
import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ICacheService } from '../../application/ports/cache.port';

@Injectable()
export class RedisCacheAdapter implements ICacheService {
  constructor(@Inject(CACHE_MANAGER) private readonly cacheManager: Cache) {}

  async get<T>(key: string): Promise<T | undefined> {
    return await this.cacheManager.get<T>(key);
  }

  async set(key: string, value: unknown, ttl?: number): Promise<void> {
    // Lưu ý: cache-manager v4/v5 có thể khác nhau đơn vị (giây vs mili-giây)
    // Với redis-store v2 + nestjs cache, thường là giây (seconds)
    await this.cacheManager.set(key, value, { ttl } as any);
  }

  async del(key: string): Promise<void> {
    await this.cacheManager.del(key);
  }

  async reset(): Promise<void> {
    await this.cacheManager.reset();
  }
}
EOF

# 5. Tạo Module Redis Cache Chuyên Biệt
log "📦 Creating Redis Cache Module..."
cat > src/core/shared/infrastructure/cache/redis-cache.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-redis-store';
import { ICacheService } from '../../application/ports/cache.port';
import { RedisCacheAdapter } from './redis-cache.adapter';
import redisConfig from '@config/redis.config';

@Global()
@Module({
  imports: [
    ConfigModule.forFeature(redisConfig),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        store: redisStore,
        host: configService.get('redis.host'),
        port: configService.get('redis.port'),
        ttl: configService.get('redis.ttl'),
        max: configService.get('redis.max'),
        // isGlobal: true, // Đã để module Global nên không bắt buộc set ở đây, nhưng set cho chắc
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    {
      provide: ICacheService,
      useClass: RedisCacheAdapter,
    },
  ],
  exports: [ICacheService],
})
export class RedisCacheModule {}
EOF

# 6. Refactor AppModule
log "🔄 Refactoring AppModule..."
cat > src/bootstrap/app.module.ts << 'EOF'
import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import databaseConfig from '@config/database.config';
import appConfig from '@config/app.config';
import loggingConfig from '@config/logging.config';
import redisConfig from '@config/redis.config'; // IMPORT CONFIG MỚI

import { CoreModule } from '@core/core.module';
import { SharedModule } from '@modules/shared/shared.module';
import { DrizzleModule } from '@database/drizzle.module';
import { LoggingModule } from '@modules/logging/logging.module';
import { RedisCacheModule } from '@core/shared/infrastructure/cache/redis-cache.module'; // IMPORT MODULE MỚI
import { RequestLoggingMiddleware } from '@api/middleware/request-logging.middleware';

import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { TestModule } from '@modules/test/test.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig, redisConfig],
    }),
    CoreModule,
    SharedModule,
    DrizzleModule,
    LoggingModule.forRootAsync(),
    RedisCacheModule, // ✅ Module Redis Global

    // Đã xóa CacheModule cũ

    UserModule,
    AuthModule,
    RbacModule,
    TestModule,
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggingMiddleware)
      .forRoutes({ path: '(.*)', method: RequestMethod.ALL });
  }
}
EOF

# 7. Refactor RbacModule (Xóa CacheModule thừa)
log "🔄 Refactoring RbacModule..."
cat > src/modules/rbac/rbac.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from '../user/user.module';
import { RoleController } from './infrastructure/controllers/role.controller';
import { RbacManagerController } from './infrastructure/controllers/rbac-manager.controller';
import { PermissionService } from './application/services/permission.service';
import { RoleService } from './application/services/role.service';
import { RbacManagerService } from './application/services/rbac-manager.service';
import { PermissionGuard } from './infrastructure/guards/permission.guard';
import { DrizzleRoleRepository, DrizzlePermissionRepository, DrizzleUserRoleRepository } from './infrastructure/persistence/repositories/drizzle-rbac.repositories';
import { IRoleRepository, IPermissionRepository, IUserRoleRepository } from './domain/repositories/rbac.repository';

@Module({
  imports: [
    UserModule,
    // Không cần import CacheModule nữa vì RedisCacheModule là Global
  ],
  controllers: [RoleController, RbacManagerController],
  providers: [
    PermissionService, RoleService, PermissionGuard, RbacManagerService,
    { provide: IRoleRepository, useClass: DrizzleRoleRepository },
    { provide: IPermissionRepository, useClass: DrizzlePermissionRepository },
    { provide: IUserRoleRepository, useClass: DrizzleUserRoleRepository },
  ],
  exports: [PermissionService, PermissionGuard, RoleService],
})
export class RbacModule {}
EOF

# 8. Refactor PermissionService (Dùng ICacheService)
log "🔄 Refactoring PermissionService..."
cat > src/modules/rbac/application/services/permission.service.ts << 'EOF'
import { Injectable, Inject } from '@nestjs/common';
import { IUserRoleRepository, IRoleRepository } from '../../domain/repositories/rbac.repository';
// IMPORT Interface
import { ICacheService } from '@core/shared/application/ports/cache.port';

@Injectable()
export class PermissionService {
  private readonly CACHE_TTL = 300; // Fallback nếu không truyền vào set()
  private readonly CACHE_PREFIX = 'rbac:permissions:';

  constructor(
    @Inject(IUserRoleRepository) private userRoleRepo: IUserRoleRepository,
    @Inject(IRoleRepository) private roleRepo: IRoleRepository,
    @Inject(ICacheService) private cacheService: ICacheService, // ✅ Inject Token
  ) {}

  async userHasPermission(userId: number, permissionName: string): Promise<boolean> {
    const cacheKey = `${this.CACHE_PREFIX}${userId}`;

    // Sử dụng abstraction layer
    const cached = await this.cacheService.get<string[]>(cacheKey);

    if (cached) return cached.includes(permissionName) || cached.includes('*');

    const userRoles = await this.userRoleRepo.findByUserId(userId);
    const activeRoles = userRoles.filter(ur => ur.isActive() && ur.role?.isActive);
    if (activeRoles.length === 0) return false;

    const roleIds = activeRoles.map(ur => ur.roleId);
    const roles = await this.roleRepo.findAllWithPermissions(roleIds);

    const permissions = new Set<string>();
    roles.forEach(r => r.permissions?.forEach(p => {
        if (p.isActive) permissions.add(p.name);
    }));

    const permArray = Array.from(permissions);

    // Cache result
    await this.cacheService.set(cacheKey, permArray);
    // Mặc định adapter sẽ lấy TTL từ config nếu không truyền,
    // hoặc bạn có thể truyền this.CACHE_TTL vào tham số thứ 3

    return permArray.includes(permissionName);
  }

  async assignRole(userId: number, roleId: number, assignedBy: number): Promise<void> {
    const existing = await this.userRoleRepo.findOne(userId, roleId);
    if (!existing) {
        const userRole: any = { userId, roleId, assignedBy, assignedAt: new Date() };
        await this.userRoleRepo.save(userRole);

        // Invalidate cache
        await this.cacheService.del(`${this.CACHE_PREFIX}${userId}`);
    }
  }
}
EOF

# 9. Kiểm tra .env (Không ghi đè)
log "📝 Checking .env configuration..."
if grep -q "REDIS_HOST" .env && grep -q "RBAC_CACHE_TTL" .env; then
  success "✅ .env file looks correct. No changes needed."
else
  warn "⚠️ Your .env might be missing REDIS or RBAC_CACHE configuration. Please verify manually."
fi

success "✅ ALL DONE! Redis implementation updated successfully."
echo "👉 Please ensure your Redis server is running at localhost:6379 (or whatever is in your .env)"
echo "👉 Restart your server: npm run start:dev"