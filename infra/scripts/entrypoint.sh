#!/bin/sh
set -e

echo "🚀 [Entrypoint] System is starting in $NODE_ENV mode..."

wait_for_db() {
  local host="$1"
  local port="$2"
  echo "🔍 Waiting for Database at $host:$port..."
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

wait_for_db "$DB_HOST" "${DB_PORT:-5432}"

export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"

# Chạy Migration
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🔄 [Migration] Syncing database schema..."
    
    # 💡 FIX: Dù ở Dev hay Prod, ta đều dùng file gốc .ts vì ta đã copy nó vào Dockerfile Runner
    SCHEMA_FILE="./src/database/schema/index.ts"

    if [ ! -f "$SCHEMA_FILE" ]; then
        echo "❌ CRITICAL: Schema file not found at $SCHEMA_FILE"
        exit 1
    fi

    # Chạy Drizzle Push (Trên Prod hệ thống sẽ tự động dùng esbuild nội bộ của drizzle-kit để đọc file .ts)
    if npx drizzle-kit push --dialect=postgresql --schema="$SCHEMA_FILE" --url="$DATABASE_URL"; then
        echo "✅ Database schema synced!"
    else
        echo "❌ Migration FAILED!"
        exit 1
    fi
fi

# Khởi chạy App
if [ "$NODE_ENV" = "development" ]; then
    echo "🛠️ [App] Starting NestJS in DEVELOPMENT mode (SWC Compiler)..."
    exec npm run start:dev
else
    echo "🚀 [App] Starting NestJS in PRODUCTION mode (Webpack Bundled)..."
    
    if [ -f "dist/src/bootstrap/main.js" ]; then
        exec node dist/src/bootstrap/main.js
    elif [ -f "dist/main.js" ]; then
        exec node dist/main.js
    elif [ -f "dist/bootstrap/main.js" ]; then
        exec node dist/bootstrap/main.js
    else
        echo "❌ Error: Cannot find bundled dist/main.js"
        exit 1
    fi
fi
