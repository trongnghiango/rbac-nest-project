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
