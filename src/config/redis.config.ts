import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  // Sử dụng biến RBAC_CACHE_TTL từ .env của bạn
  ttl: parseInt(process.env.RBAC_CACHE_TTL || '300', 10),
  max: parseInt(process.env.RBAC_CACHE_MAX || '1000', 10),
}));
