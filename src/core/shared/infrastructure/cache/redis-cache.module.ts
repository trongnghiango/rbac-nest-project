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
        const uri = configService.get<string>('redis.uri');
        const host = configService.get<string>('redis.host');
        const port = configService.get<number>('redis.port');
        const ttl = (configService.get<number>('redis.ttl') || 300) * 1000;
        const password = configService.get<string>('redis.password');
        // --- BẮT ĐẦU LOGIC CHUYỂN ĐỔI ---
        
        // Cấu hình chung (Reconnect strategy luôn cần thiết)
        const baseSocketConfig = {
          reconnectStrategy: (retries: number) => Math.min(retries * 50, 3000),
        };

        let storeConfig: any = {
          ttl,
        };

        if (uri) {
          // ☁️ CASE 1: Dùng URI (Redis Cloud / Production)
          console.log(`🔌 [Redis] Connecting via URI...`);
          storeConfig = {
            ...storeConfig,
            url: uri, // redis-yet (node-redis) sẽ tự parse user/pass/tls từ chuỗi này
            socket: {
              ...baseSocketConfig,
              // Nếu URI là 'rediss://' (có 's'), node-redis tự bật TLS
              // Nếu cần custom TLS (như bỏ check cert), thêm tls: { rejectUnauthorized: false } vào đây
            },
          };
        } else {
          // 🐳 CASE 2: Dùng Host/Port (Docker Local)
          console.log(`🔌 [Redis] Connecting via Host: ${host}, Port: ${port}`);
          storeConfig = {
            ...storeConfig,
            password: password, // Thêm password nếu có
            socket: {
              host,
              port,
              ...baseSocketConfig,
            },
          };
        }

        // Tạo Store
        const store = await redisStore(storeConfig);
        // --- KẾT THÚC LOGIC CHUYỂN ĐỔI ---


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
