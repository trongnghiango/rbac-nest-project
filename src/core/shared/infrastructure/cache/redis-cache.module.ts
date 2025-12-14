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
        const host = configService.get('redis.host');
        const port = configService.get('redis.port');
        const ttl = (configService.get('redis.ttl') || 300) * 1000;

        console.log(`🔌 Connecting to Redis at ${host}:${port}...`);

        // 1. Tạo Store
        const store = await redisStore({
          socket: { host, port },
          ttl,
        });
        console.log('✅ Redis Store Created!');

        // 2. Load thư viện
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cm = require('cache-manager');

        // 3. Ưu tiên createCache (v5), fallback sang caching (v4)
        // QUAN TRỌNG: Truyền object config thay vì instance nếu cần thiết,
        // nhưng với redis-yet thì truyền instance là chuẩn.
        const createCache =
          cm.createCache ||
          (cm.default && cm.default.createCache) ||
          cm.caching;

        if (!createCache) throw new Error('Cannot find createCache function');

        // Tạo cache manager từ store
        const cache = createCache(store);

        // Gán ngược store vào cache object nếu thư viện không tự gán (để Adapter check được)
        if (!cache.store) {
          cache.store = store;
        }

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
