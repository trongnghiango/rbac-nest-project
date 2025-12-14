#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🔌 FIXING REDIS CONNECTION LOGIC..."

# Ghi đè lại file RedisCacheModule với cách import đúng (dùng require)
cat > src/core/shared/infrastructure/cache/redis-cache.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
import { RedisCacheAdapter } from './redis-cache.adapter';
import redisConfig from '@config/redis.config';

// ⚠️ QUAN TRỌNG: Sử dụng require thay vì import * as ...
// Điều này giúp NestJS load đúng driver redis-store v2
// eslint-disable-next-line @typescript-eslint/no-var-requires
const redisStore = require('cache-manager-redis-store');

@Global()
@Module({
  imports: [
    ConfigModule.forFeature(redisConfig),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        return {
          store: redisStore, // Driver Redis thực sự
          host: configService.get('redis.host'),
          port: configService.get('redis.port'),
          ttl: configService.get('redis.ttl'),
          max: configService.get('redis.max'),
          // isGlobal: true, // Đã khai báo @Global ở trên class
        };
      },
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

success "✅ REDIS MODULE FIXED! Now using 'require' for proper driver loading."
echo "👉 Please restart your server: npm run start:dev"
echo "👉 TEST 1: Turn OFF Redis -> Call API -> You should see 'Redis GET Error' (Connection Refused)"
echo "👉 TEST 2: Turn ON Redis  -> Call API -> You should see duration > 0ms"