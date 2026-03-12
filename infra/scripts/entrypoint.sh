#!/bin/sh
set -e

echo "🚀 [Entrypoint] System is starting in $NODE_ENV mode..."

# Hàm chờ Database
wait_for_db() {
  local host="$1"
  local port="$2"
  echo "🔍 Waiting for Database at $host:$port..."
  # Đợi tối đa 30s để tránh loop vô hạn
  local timeout=30
  while ! nc -z "$host" "$port" 2>/dev/null; do
    timeout=$((timeout - 1))
    if [ "$timeout" -le 0 ]; then
      echo "❌ Database unavailable after 30 seconds. Exiting!"
      exit 1
    fi
    sleep 1
  done
  echo "✅ Database is UP!"
}

# Đợi DB sẵn sàng
wait_for_db "$DB_HOST" "$DB_PORT"

# Cấu hình Connection String cho Drizzle
export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"

# Chạy Migration
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🔄 [Migration] Syncing database schema..."
    
    # Phân biệt đường dẫn schema giữa dev và prod
    if [ "$NODE_ENV" = "production" ]; then
        SCHEMA_FILE="./dist/src/database/schema/index.js"
    else
        SCHEMA_FILE="./src/database/schema/index.ts"
    fi

    if [ ! -f "$SCHEMA_FILE" ]; then
        echo "❌ CRITICAL: Schema file not found at $SCHEMA_FILE"
        exit 1
    fi

    # CẢNH BÁO: Drizzle push có thể gây mất data nếu rename cột. 
    # Về lâu dài hãy thay bằng lệnh migrate. Hiện tại tối ưu lệnh push:
    if npx drizzle-kit push --dialect=postgresql --schema="$SCHEMA_FILE" --url="$DATABASE_URL"; then
        echo "✅ Database schema synced!"
    else
        echo "❌ Migration FAILED!"
        exit 1
    fi
fi

# Khởi chạy App theo môi trường
if [ "$NODE_ENV" = "development" ]; then
    echo "🛠️ [App] Starting NestJS in DEVELOPMENT mode..."
    exec npm run start:dev
else
    echo "🚀 [App] Starting NestJS in PRODUCTION mode..."
    if [ -f "dist/src/bootstrap/main.js" ]; then
        exec node dist/src/bootstrap/main.js
    elif [ -f "dist/bootstrap/main.js" ]; then
        exec node dist/bootstrap/main.js
    else
        echo "❌ Error: Cannot find main.js"
        exit 1
    fi
fi
