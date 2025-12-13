import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache as RootCache } from 'cache-manager';
import { ICacheService } from '../../application/ports/cache.port';
// 1. Import Logger Port và Token
import { ILogger, LOGGER_TOKEN } from '../../application/ports/logger.port';

interface ExtendedCache extends Omit<RootCache, 'clear'> {
  clear?: () => Promise<void | boolean>;
  reset?: () => Promise<void>;
}

@Injectable()
export class RedisCacheAdapter implements ICacheService {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: ExtendedCache,
    // 2. Inject Logger vào Adapter
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  async get<T>(key: string): Promise<T | undefined> {
    const start = Date.now();
    const value = await this.cacheManager.get<T>(key);

    // 3. Log Debug (Thay vì Info để tránh spam log production)
    this.logger.debug(`Redis GET`, {
      key,
      hit: !!value,
      duration: `${Date.now() - start}ms`,
    });

    return value;
  }

  async set(key: string, value: unknown, ttl?: number): Promise<void> {
    // Log Debug
    this.logger.debug(`Redis SET`, { key, ttl });

    await (this.cacheManager as unknown as RootCache).set(key, value, ttl ?? 0);
  }

  async del(key: string): Promise<void> {
    this.logger.debug(`Redis DEL`, { key });
    await this.cacheManager.del(key);
  }

  async reset(): Promise<void> {
    this.logger.warn(`Redis RESET ALL`); // Warn vì đây là hành động nguy hiểm

    if (this.cacheManager.clear) {
      await this.cacheManager.clear();
      return;
    }

    if (this.cacheManager.reset) {
      await this.cacheManager.reset();
    }
  }
}
