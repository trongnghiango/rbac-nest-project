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

        // Sử dụng redis-yet (chuẩn mới)
        const store = await redisStore({
          socket: { host, port },
          ttl,
        });

        console.log('✅ Redis Store Created!');

        // Fix lỗi import cache-manager (CommonJS vs ESM)
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cm = require('cache-manager');
        const createCache =
          cm.createCache ||
          (cm.default && cm.default.createCache) ||
          cm.caching;

        if (!createCache) throw new Error('Cannot find createCache function');

        const cache = createCache(store);
        // Gán ngược store để Adapter check được
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
