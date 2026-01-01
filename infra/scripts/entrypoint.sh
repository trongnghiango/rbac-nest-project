#!/bin/sh
set -e

echo "🔍 [Entrypoint] Starting PRODUCTION (Hardcore Mode)..."

wait_for_db() {
  local host="$1"
  local port="$2"
  until nc -z "$host" "$port" 2>/dev/null; do
    echo "   ⏳ Postgres unavailable..."
    sleep 2
  done
  echo "   ✅ Postgres UP!"
}

wait_for_db "$DB_HOST" "5432"

# Setup biến môi trường
export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"

if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🚀 [Migration] Running drizzle-kit push (DIRECT JS)..."

    # 👇 KIỂM TRA FILE CÓ TỒN TẠI KHÔNG TRƯỚC KHI CHẠY
    SCHEMA_FILE="./dist/src/database/schema/index.js"

    if [ ! -f "$SCHEMA_FILE" ]; then
        echo "❌ CRITICAL: Schema file not found at $SCHEMA_FILE"
        echo "📂 Listing dist structure:"
        find dist -maxdepth 4
        exit 1
    fi

    # 👇 LỆNH QUAN TRỌNG NHẤT:
    # Truyền thẳng --schema trỏ vào file JS.
    # Truyền thẳng --url.
    # Không dùng file config nữa.
    if npx drizzle-kit push --dialect=postgresql --schema="$SCHEMA_FILE" --url="$DATABASE_URL"; then
        echo "   ✅ Database schema synced!"
    else
        echo "   ❌ Migration FAILED!"
        exit 1
    fi
fi

echo "🚀 [App] Starting NestJS..."
# Logic tìm main.js
if [ -f "dist/src/bootstrap/main.js" ]; then
  exec node dist/src/bootstrap/main.js
elif [ -f "dist/bootstrap/main.js" ]; then
  exec node dist/bootstrap/main.js
else
  echo "❌ Error: Cannot find main.js"
  exit 1
fi