// Token để Inject
export const ICacheService = Symbol('ICacheService');

// Interface trừu tượng
export interface ICacheService {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  reset(): Promise<void>;
}
