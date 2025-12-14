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
    const store: any = (this.cacheManager as any).store;

    // --- DEBUG BLOCK ---
    const storeName = store?.name || store?.constructor?.name || 'Unknown';
    this.logger.info(`🔍 DEBUG: Cache Store Name = [${storeName}]`);

    // Kiểm tra xem có phải Redis không
    const isRedis = storeName === 'RedisStore' || (store && store.client);

    if (isRedis) {
      this.logger.info('🚀 CACHE STATUS: REDIS IS ACTIVE (Confirmed)');
    } else {
      this.logger.warn(
        '⚠️ CACHE STATUS: NOT REDIS! INSPECTING STORE OBJECT...',
      );
      console.log('Store Keys:', Object.keys(store || {}));
    }
    // -------------------
  }

  async get<T>(key: string): Promise<T | undefined> {
    try {
      const start = Date.now();
      const value = await this.cacheManager.get<T>(key);

      // Chỉ log debug
      this.logger.debug(`Redis GET`, {
        key,
        hit: !!value,
        duration: `${Date.now() - start}ms`,
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
      this.logger.debug(`Redis SET`, { key });
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
      this.logger.warn(`Redis RESET ALL`);
    } catch (error) {
      this.logger.error(`Redis RESET Error`, error as Error);
    }
  }
}
