#!/bin/sh
set -e

echo "🚀 [Entrypoint] System is starting in $NODE_ENV mode..."

# 1. KẾT NỐI DATABASE CHUẨN XÁC
wait_for_db() {
  local host="$1"
  local port="${2:-5432}"
  local user="$DB_USERNAME"
  echo "🔍 Waiting for Database at $host:$port..."
  
  local timeout=30
  # Sử dụng pg_isready thay vì netcat để đảm bảo Postgres thực sự sẵn sàng nhận Query
  while ! pg_isready -h "$host" -p "$port" -U "$user" > /dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ "$timeout" -le 0 ]; then
      echo "❌ Database unavailable after 30 seconds. Exiting!"
      exit 1
    fi
    sleep 1
  done
  echo "✅ Database is UP and ready to accept connections!"
}

wait_for_db "$DB_HOST" "$DB_PORT"

# 2. XỬ LÝ MIGRATION AN TOÀN
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🔄 [Migration] Syncing database schema..."
    
    if [ "$NODE_ENV" = "development" ]; then
        # Ở môi trường Dev, dùng lệnh push để code nhanh
        SCHEMA_FILE="./src/database/schema/index.ts"
        export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"
        
        if npx drizzle-kit push --dialect=postgresql --schema="$SCHEMA_FILE" --url="$DATABASE_URL"; then
            echo "✅ Dev Database schema synced!"
        else
            echo "❌ Dev Migration FAILED!"
            exit 1
        fi
    else
        # Ở môi trường Prod: CẦN CHẠY BẰNG SCRIPT ĐÃ COMPILE RA JS
        # Không dùng npx, không dùng file .ts ở Prod
        # Yêu cầu: Bạn cần viết 1 file src/database/migrate.ts và build ra dist/database/migrate.js
        MIGRATE_SCRIPT="./dist/database/migrate.js"
        
        if [ -f "$MIGRATE_SCRIPT" ]; then
            if node "$MIGRATE_SCRIPT"; then
                echo "✅ Prod Database migration completed!"
            else
                echo "❌ Prod Migration FAILED!"
                exit 1
            fi
        else
            echo "⚠️ Warning: Migration script not found at $MIGRATE_SCRIPT. Skipping migration."
        fi
    fi
fi

# 3. KHỞI CHẠY APP
if [ "$NODE_ENV" = "development" ]; then
    echo "🛠️ [App] Starting NestJS in DEVELOPMENT mode..."
    exec npm run start:dev
else
    echo "🚀 [App] Starting NestJS in PRODUCTION mode..."
    
    # Tìm đúng file main.js đã được Webpack/NestJS compile
    if [ -f "dist/src/bootstrap/main.js" ]; then
        exec node dist/src/bootstrap/main.js
    elif [ -f "dist/main.js" ]; then
        exec node dist/main.js
    elif [ -f "dist/bootstrap/main.js" ]; then
        exec node dist/bootstrap/main.js
    else
        echo "❌ Error: Cannot find bundled dist/main.js. Check your Webpack/NestJS build config."
        ls -la dist/
        exit 1
    fi
fi
