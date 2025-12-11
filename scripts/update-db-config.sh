#!/bin/bash

BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }

log "🚀 UPDATING DATABASE CONFIGURATION FOR HYBRID (LOCAL/CLOUD)..."

# Cập nhật file config database
cat > src/config/database.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  // Cấu hình chung cho cả 2 môi trường
  const commonConfig = {
    type: 'postgres',
    synchronize: process.env.NODE_ENV === 'development', // Tắt trên production nhé
    logging: process.env.NODE_ENV === 'development',
    autoLoadEntities: true,
  };

  // 1. Ưu tiên chế độ CLOUD (Neon, Render, Supabase...)
  // Nếu có biến DATABASE_URL thì dùng luôn chuỗi kết nối
  if (process.env.DATABASE_URL) {
    console.log('📡 Using Database Connection String (Cloud/Neon)');
    return {
      ...commonConfig,
      url: process.env.DATABASE_URL,
      // Neon và các cloud DB thường yêu cầu SSL
      ssl: {
        rejectUnauthorized: false, // Chấp nhận chứng chỉ SSL của Neon
      },
    };
  }

  // 2. Chế độ LOCAL (Fallback)
  console.log('💻 Using Local Database Configuration');
  return {
    ...commonConfig,
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_DATABASE || 'rbac_system',
    // Local thường không cần SSL
    ssl: process.env.DB_SSL === 'true',
  };
});
EOF

log "✅ Database config updated successfully!"
