#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

ensure_dir() { mkdir -p "$@"; }

log "🚀 SETTING UP DATABASE MIGRATIONS (PRO LEVEL)..."

# 1. Tạo thư mục chứa Migrations
ensure_dir src/database/migrations

# 2. Tạo File Migration đầu tiên: Add Attributes
# File này chứa lệnh SQL để thêm cột an toàn
cat > src/database/migrations/1700000000000-add-attributes-to-permission.ts << 'EOF'
import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddAttributesToPermission1700000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Lấy thông tin bảng permissions
    const table = await queryRunner.getTable('permissions');

    // 2. Kiểm tra xem cột 'attributes' đã tồn tại chưa
    const attributeColumn = table?.findColumnByName('attributes');

    // 3. Nếu chưa có thì thêm vào
    if (!attributeColumn) {
      await queryRunner.addColumn(
        'permissions',
        new TableColumn({
          name: 'attributes',
          type: 'varchar',
          default: "'*'", // Mặc định là dấu sao (Full quyền)
          isNullable: false,
        }),
      );
      console.log('✅ MIGRATION: Added "attributes" column to "permissions" table.');
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Logic Rollback: Nếu chạy revert thì xóa cột đi
    const table = await queryRunner.getTable('permissions');
    const attributeColumn = table?.findColumnByName('attributes');

    if (attributeColumn) {
      await queryRunner.dropColumn('permissions', 'attributes');
    }
  }
}
EOF

# 3. Cập nhật Database Config để chạy Migrations
# Thêm migrationsRun: true và đường dẫn tới folder migrations
cat > src/config/database.config.ts << 'EOF'
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => {
  const isDev = process.env.NODE_ENV === 'development';

  return {
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'postgres',
    database: process.env.DB_NAME || 'rbac_system',

    // PRO TIP:
    // Trên Production nên tắt synchronize (false) và dùng migrationsRun (true)
    // Ở Dev có thể để synchronize true cho lẹ, nhưng dùng Migration an toàn hơn
    synchronize: isDev,
    logging: isDev ? ['error', 'warn', 'migration'] : ['error'],

    // --- MIGRATION CONFIG ---
    migrationsRun: true, // Tự động chạy migration khi start app
    migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
    // ------------------------

    autoLoadEntities: true,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  };
});
EOF

# 4. Cập nhật App Module để load Migration
# (Thực ra bước update config ở trên đã đủ, nhưng ta update lại App Module
# để đảm bảo nó load đúng file config mới nhất)
cat > src/bootstrap/app.module.ts << 'EOF'
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';

import databaseConfig from '../config/database.config';
import appConfig from '../config/app.config';
import loggingConfig from '../config/logging.config';

import { CoreModule } from '../core/core.module';
import { SharedModule } from '../modules/shared/shared.module';
import { UserModule } from '../modules/user/user.module';
import { AuthModule } from '../modules/auth/auth.module';
import { RbacModule } from '../modules/rbac/rbac.module';
import { TestModule } from '../modules/test/test.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [databaseConfig, appConfig, loggingConfig],
    }),
    CoreModule,
    SharedModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        const dbConfig = config.get('database');
        return {
          ...dbConfig,
          // Load cả Entities và Migrations
          entities: [__dirname + '/../**/*.orm-entity{.ts,.js}'],
        };
      },
      inject: [ConfigService],
    }),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: () => ({ ttl: 300, max: 100 }),
      inject: [ConfigService],
    }),
    UserModule,
    AuthModule,
    RbacModule,
    TestModule,
  ],
})
export class AppModule {}
EOF

success "✅ MIGRATION SETUP COMPLETED!"
echo "👉 System will now automatically check and add missing columns on startup."
echo "👉 Run: docker-compose up -d --build"
