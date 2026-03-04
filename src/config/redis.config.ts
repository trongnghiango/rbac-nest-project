import { registerAs } from '@nestjs/config';

export default registerAs('redis', () => ({
  // 1. Ưu tiên URI (Dành cho Redis Cloud)
  uri: process.env.REDIS_URI,

  // 2. Fallback Host/Port (Dành cho Docker Local)
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  
  // Mật khẩu (Có thể dùng cho cả local nếu docker set pass)
  password: process.env.REDIS_PASSWORD,

  // Sử dụng biến RBAC_CACHE_TTL từ .env của bạn
  ttl: parseInt(process.env.RBAC_CACHE_TTL || '300', 10),
  max: parseInt(process.env.RBAC_CACHE_MAX || '1000', 10),
}));
