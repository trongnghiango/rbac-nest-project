#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🧹 CLEANING UP DEBUG CODE & FINALIZING..."

# 1. Clean Redis Module (Giữ lại logic Factory chuẩn nhưng bỏ log thừa)
cat > src/core/shared/infrastructure/cache/redis-cache.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
import { RedisCacheAdapter } from './redis-cache.adapter';
import redisConfig from '@config/redis.config';
import { redisStore } from 'cache-manager-redis-yet';

@Global()
@Module({
  imports: [ConfigModule.forFeature(redisConfig)],
  providers: [
    {
      provide: CACHE_MANAGER,
      useFactory: async (configService: ConfigService) => {
        const store = await redisStore({
          socket: {
            host: configService.get('redis.host'),
            port: configService.get('redis.port'),
          },
          ttl: (configService.get('redis.ttl') || 300) * 1000,
        });

        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cm = require('cache-manager');
        const createCache = cm.createCache || (cm.default && cm.default.createCache) || cm.caching;

        if (!createCache) throw new Error('Cannot find createCache function');

        const cache = createCache(store);
        if (!cache.store) cache.store = store;

        return cache;
      },
      inject: [ConfigService],
    },
    {
      provide: ICacheService,
      useClass: RedisCacheAdapter,
    },
  ],
  exports: [ICacheService, CACHE_MANAGER],
})
export class RedisCacheModule {}
EOF

# 2. Clean Redis Adapter (Bỏ log debug store structure)
cat > src/core/shared/infrastructure/cache/redis-cache.adapter.ts << 'EOF'
import { Injectable, Inject, OnModuleInit } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
import { ILogger, LOGGER_TOKEN } from '../../application/ports/logger.port';

@Injectable()
export class RedisCacheAdapter implements ICacheService, OnModuleInit {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  onModuleInit() {
    this.logger.info('🚀 Redis Cache Adapter initialized successfully.');
  }

  async get<T>(key: string): Promise<T | undefined> {
    try {
      const start = process.hrtime(); // Dùng hrtime để đo chính xác hơn (nano giây)
      const value = await this.cacheManager.get<T>(key);
      const end = process.hrtime(start);
      const durationMs = (end[0] * 1000 + end[1] / 1e6).toFixed(2); // Chuyển đổi ra ms (có số lẻ)

      this.logger.debug(`Redis GET`, {
        key,
        hit: !!value,
        duration: `${durationMs}ms`
      });

      return value;
    } catch (error) {
      this.logger.error(`Redis GET Error`, error as Error);
      return undefined;
    }
  }

  async set(key: string, value: unknown, ttl?: number): Promise<void> {
    try {
      const finalTtl = ttl ? ttl * 1000 : undefined;
      await this.cacheManager.set(key, value, finalTtl as any);
      this.logger.debug(`Redis SET`, { key, ttl });
    } catch (error) {
      this.logger.error(`Redis SET Error`, error as Error);
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.cacheManager.del(key);
      this.logger.debug(`Redis DEL`, { key });
    } catch (error) {
      this.logger.error(`Redis DEL Error`, error as Error);
    }
  }

  async reset(): Promise<void> {
    try {
      const client = this.cacheManager as any;
      if (client.store && typeof client.store.clear === 'function') {
          await client.store.clear();
      } else if (typeof client.reset === 'function') {
          await client.reset();
      }
      this.logger.warn(`Redis RESET ALL executed`);
    } catch (error) {
      this.logger.error(`Redis RESET Error`, error as Error);
    }
  }
}
EOF

# 3. Fix Warning 'Unsupported route path' trong AppModule
# NestJS v10 + path-to-regexp mới yêu cầu cú pháp khác cho wildcard route
log "🔧 Fixing Middleware Route Path Warning..."
cat > src/bootstrap/app.module.ts << 'EOF'
import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import databaseConfig from '@config/database.config';
import appConfig from '@config/app.config';
import loggingConfig from '@config/logging.config';
import redisConfig from '@config/redis.config';
import eventBusConfig from '@config/event-bus.config';

import { CoreModule } from '@core/core.module';
import { SharedModule } from '@modules/shared/shared.module';
import { DrizzleModule } from '@database/drizzle.module';
import { LoggingModule } from '@modules/logging/logging.module';
import { RedisCacheModule } from '@core/shared/infrastructure/cache/redis-cache.module';
import { RequestLoggingMiddleware } from '@api/middleware/request-logging.middleware';

import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { RbacModule } from '@modules/rbac/rbac.module';
import { TestModule } from '@modules/test/test.module';
import { NotificationModule } from '@modules/notification/notification.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [
        databaseConfig,
        appConfig,
        loggingConfig,
        redisConfig,
        eventBusConfig,
      ],
    }),
    CoreModule,
    SharedModule,
    DrizzleModule,
    LoggingModule.forRootAsync(),
    RedisCacheModule,

    UserModule,
    AuthModule,
    RbacModule,
    NotificationModule,
    TestModule,
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(RequestLoggingMiddleware)
      // Fix: Dùng '{*path}' thay vì '(.*)' cho NestJS v10 mới nhất
      .forRoutes({ path: '{*path}', method: RequestMethod.ALL });
  }
}
EOF

success "✨ CLEANUP COMPLETED! Your project is now Polished & Professional."
echo "👉 Restart server: npm run start:dev"