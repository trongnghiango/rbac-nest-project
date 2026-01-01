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
        const host = configService.get<string>('redis.host');
        const port = configService.get<number>('redis.port');
        const ttl = (configService.get('redis.ttl') || 300) * 1000;

        // Cấu hình Redis Store
        const store = await redisStore({
          socket: {
            host,
            port,
            // Thử kết nối lại tối đa sau mỗi 3 giây
            reconnectStrategy: (retries) => Math.min(retries * 50, 3000),
          },
          ttl,
        });

        // 👇 TRUY CẬP VÀO CLIENT GỐC ĐỂ LẮNG NGHE SỰ KIỆN 👇
        const client = (store as any).client;
        if (client) {
          // 1. Khi bị lỗi kết nối (để tránh crash app)
          client.on('error', (err: any) => {
            console.error(`❌ [Redis] Connection Error: ${err.message}`);
          });

          // 2. Khi đang cố gắng kết nối lại
          client.on('reconnecting', () => {
            console.warn('⏳ [Redis] Lost connection! Reconnecting...');
          });

          // 3. ✅ KHI ĐÃ KẾT NỐI LẠI THÀNH CÔNG VÀ SẴN SÀNG
          client.on('ready', () => {
            console.log('🚀 [Redis] Connection ESTABLISHED & READY!');
          });
        }

        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cm = require('cache-manager');
        const createCache =
          cm.createCache ||
          (cm.default && cm.default.createCache) ||
          cm.caching;
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
