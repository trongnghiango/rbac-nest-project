#!/bin/sh
set -e

echo "🔍 [Entrypoint] Đang kiểm tra Database..."

# Hàm kiểm tra cổng TCP bằng /dev/tcp (Bash native) hoặc nc nếu có
wait_for_db() {
  local host="$1"
  local port="$2"
  local retries=30
  local wait=2

  until nc -z "$host" "$port" 2>/dev/null; do
    echo "   ⏳ Postgres ($host:$port) chưa sẵn sàng... thử lại sau ${wait}s ($retries còn lại)"
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
      echo "   ❌ Timeout: Không thể kết nối Database!"
      exit 1
    fi
    sleep $wait
  done
  echo "   ✅ Postgres đã sẵn sàng kết nối!"
}

# Gọi hàm wait
wait_for_db "$DB_HOST" "5432"

# Setup biến môi trường DB URL (nếu chưa có)
if [ -z "$DATABASE_URL" ]; then
  export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}"
fi

# Chạy Migration
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🚀 [Migration] Đang chạy Drizzle Kit Push..."

    # Chạy npx drizzle-kit push
    # Lưu ý: Cần đảm bảo drizzle-kit có trong dependencies hoặc devDependencies (và chưa bị prune)
    if npx drizzle-kit push; then
        echo "   ✅ Database schema đã được cập nhật!"
    else
        echo "   ❌ Migration thất bại! Kiểm tra lại cấu hình DB."
        # Trong PROD, có thể bạn muốn exit 1. Trong DEV, có thể bỏ qua để debug.
        # exit 1
    fi
fi

# Chạy Seed (Optional)
if [ "$RUN_SEEDS" = "true" ]; then
    echo "🌱 [Seeder] Đang chạy seed dữ liệu..."
    # Logic chạy seed của bạn, ví dụ: node dist/src/bootstrap/seed.js
fi

echo "🚀 [App] Khởi động NestJS..."

# Sử dụng exec để node thay thế process shell hiện tại (nhận signal SIGTERM đúng cách)
if [ "$NODE_ENV" = "development" ]; then
  exec npm run start:debug -- --watch
else
  exec node dist/bootstrap/main.js
fi