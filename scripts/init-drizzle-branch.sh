#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

ensure_dir() { mkdir -p "$@"; }

log "🚀 PREPARING DRIZZLE ORM BRANCH..."

# ============================================
# 1. GIT BRANCHING
# ============================================
log "1. Creating/Switching to branch 'refactor/drizzle-orm'..."

if [ -d .git ]; then
    # Thử tạo nhánh mới, nếu tồn tại rồi thì checkout sang
    git checkout -b refactor/drizzle-orm 2>/dev/null || git checkout refactor/drizzle-orm
    success "Switched to branch: refactor/drizzle-orm"
else
    error "Not a git repository. Please init git first."
fi

# ============================================
# 2. SWAP DEPENDENCIES
# ============================================
log "2. Swapping ORM Dependencies..."

# Gỡ TypeORM
npm uninstall @nestjs/typeorm typeorm

# Cài Drizzle & Postgres driver
npm install drizzle-orm pg
npm install -D drizzle-kit @types/pg

success "Dependencies updated."

# ============================================
# 3. SETUP DRIZZLE INFRASTRUCTURE
# ============================================
log "3. Setting up Drizzle Infrastructure..."

ensure_dir src/database/schema

# 3.1 Config cho Drizzle Kit (CLI)
cat > drizzle.config.ts << 'EOF'
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/database/schema/*.schema.ts',
  out: './src/database/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || `postgres://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
  },
  verbose: true,
  strict: true,
});
EOF

# 3.2 Drizzle Provider (Kết nối DB)
cat > src/database/drizzle.provider.ts << 'EOF'
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { ConfigService } from '@nestjs/config';
import * as schema from './schema';

export const DRIZZLE = 'DRIZZLE_CONNECTION';

export const drizzleProvider = {
  provide: DRIZZLE,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const connectionString = configService.get<string>('database.url');

    // Config cho cả Local và Cloud
    const host = configService.get<string>('database.host');
    const port = configService.get<number>('database.port');
    const user = configService.get<string>('database.username');
    const password = configService.get<string>('database.password');
    const database = configService.get<string>('database.database');

    const poolConfig = connectionString
      ? { connectionString }
      : { host, port, user, password, database };

    const pool = new Pool(poolConfig);

    return drizzle(pool, { schema });
  },
};
EOF

# 3.3 Drizzle Module
cat > src/database/drizzle.module.ts << 'EOF'
import { Module, Global } from '@nestjs/common';
import { drizzleProvider } from './drizzle.provider';
import { ConfigModule } from '@nestjs/config';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [drizzleProvider],
  exports: [drizzleProvider],
})
export class DrizzleModule {}
EOF

# 3.4 Barrel file cho Schema
cat > src/database/schema/index.ts << 'EOF'
// Export schemas here
// export * from './users.schema';
EOF

# ============================================
# 4. UPDATE DATABASE CONFIG
# ============================================
log "4. Updating Database Config for Drizzle..."

cat > src/config/database.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  // Ưu tiên Connection String (Cloud)
  if (process.env.DATABASE_URL) {
    return { url: process.env.DATABASE_URL };
  }

  // Fallback Local
  return {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'rbac_system',
  };
});
EOF

success "✅ BRANCH READY & DRIZZLE INSTALLED!"
