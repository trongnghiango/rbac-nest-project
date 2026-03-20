## File: infra/docker/Dockerfile.dev
```
FROM node:22.15-alpine

WORKDIR /app

# 1. Cài đặt thư viện hệ thống (Giữ nguyên vì Alpine cần C++ compiler)
RUN apk add --no-cache \
    build-base gcc g++ autoconf automake zlib-dev libtool \
    python3 make nasm vips-dev git linux-headers procps

# 2. KÍCH HOẠT PNPM
RUN corepack enable && corepack prepare pnpm@latest --activate

# 3. Copy file config và lockfile của pnpm
COPY package.json pnpm-lock.yaml* ./

# 4. Cài đặt dependencies bằng pnpm
RUN pnpm install --frozen-lockfile

# 5. Copy toàn bộ source code
COPY . .

ENV NODE_ENV=development

# Setup entrypoint
COPY infra/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 9229

CMD ["/entrypoint.sh"]

```

## File: infra/docker/Dockerfile
```
# STAGE 1: BASE
FROM node:22.15-alpine AS base
RUN apk add --no-cache libc6-compat
# Kích hoạt pnpm ở Base để các stage sau đều dùng được
RUN corepack enable && corepack prepare pnpm@latest --activate

# STAGE 2: DEPS
FROM base AS deps
WORKDIR /app
RUN apk add --no-cache build-base gcc g++ autoconf automake zlib-dev libtool python3 make nasm vips-dev git linux-headers
COPY package.json pnpm-lock.yaml* ./
# Dùng pnpm để cài deps (giống hệt npm ci nhưng cho pnpm)
RUN pnpm install --frozen-lockfile

# STAGE 3: BUILDER
FROM base AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Dùng pnpm build
RUN pnpm run build

# STAGE 4: RUNNER (Production)
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Ho_Chi_Minh \
    PORT=8080

RUN apk add --no-cache dumb-init vips tzdata ca-certificates curl \
    && update-ca-certificates

RUN addgroup -g 1001 -S nodejs && adduser -S -u 1001 -G nodejs appuser
RUN mkdir -p /app/uploads/dental/temp /app/uploads/dental/converted /app/logs \
    && chown -R appuser:nodejs /app

COPY --from=builder --chown=appuser:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:nodejs /app/dist ./dist
COPY --from=builder --chown=appuser:nodejs /app/package.json ./

COPY infra/scripts/entrypoint.sh /entrypoint.sh
COPY infra/scripts/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh && chown appuser:nodejs /entrypoint.sh /healthcheck.sh

USER appuser
EXPOSE 8080

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]

```

## File: infra/docker-compose.prod.yml
```
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: rbac_postgres_prod
    restart: always
    env_file:
      - ../.env.production
    environment:
      POSTGRES_USER: ${DB_USERNAME:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}
      POSTGRES_DB: ${DB_NAME:-rbac_system}
    volumes:
      - pgdata_prod:/var/lib/postgresql/data
    networks:
      - rbac_prod_net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USERNAME:-postgres} -d ${DB_NAME:-rbac_system}"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G

  redis:
    image: redis:7-alpine
    container_name: rbac_redis_prod
    restart: always
    networks:
      - rbac_prod_net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M

  # 👇 THÊM SERVICE TELEGRAM LOCAL VÀO ĐÂY
  telegram-api:
    image: aiogram/telegram-bot-api:latest
    container_name: rbac_telegram_api_prod
    restart: always
    env_file:
      - ../.env.production
    environment:
      TELEGRAM_API_ID: ${TELEGRAM_API_ID}
      TELEGRAM_API_HASH: ${TELEGRAM_API_HASH}
      TELEGRAM_STAT: 1
      TELEGRAM_LOCAL: 1
    volumes:
      - ${TELEGRAM_LOCAL_ROOT:-./telegram-data}:/var/lib/telegram-bot-api
    networks:
      - rbac_prod_net
    deploy:
      resources:
        limits:
          memory: 512M

  api:
    build:
      context: ..
      dockerfile: infra/docker/Dockerfile
    container_name: rbac_api_prod
    restart: always
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      telegram-api:
        condition: service_started
    env_file:
      - ../.env.production
    environment:
      - RUN_MIGRATIONS=true
      - NODE_OPTIONS=--max-old-space-size=1536
      - TELEGRAM_API_ROOT=http://telegram-api:8081
    volumes:
      - dental_data_prod:/app/uploads
      - api_logs_prod:/app/logs
      # Map chung thư mục data Telegram
      - ${TELEGRAM_LOCAL_ROOT:-./telegram-data}:/app/telegram-data
    ports:
      - "${PORT:-8080}:8080"
    networks:
      - rbac_prod_net
    healthcheck:
      test: ["CMD", "/healthcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G

networks:
  rbac_prod_net:
    driver: bridge

volumes:
  pgdata_prod:
  dental_data_prod:
  api_logs_prod:

```

## File: infra/docker-compose.dev.yml
```

services:
  postgres:
    image: postgres:15-alpine
    container_name: rbac_postgres_dev
    restart: unless-stopped
    env_file:
      - ../.env.development
    environment:
      POSTGRES_USER: ${DB_USERNAME:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}
      POSTGRES_DB: ${DB_NAME:-rbac_system}
    volumes:
      - pgdata_dev:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - rbac_dev_net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USERNAME:-postgres} -d ${DB_NAME:-rbac_system}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: rbac_redis_dev
    restart: unless-stopped
    ports:
      - "6379:6379"
    networks:
      - rbac_dev_net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  # 👇 THÊM SERVICE TELEGRAM LOCAL VÀO ĐÂY
  telegram-api:
    image: aiogram/telegram-bot-api:latest
    container_name: rbac_telegram_api_dev
    restart: unless-stopped
    env_file:
      - ../.env.development
    environment:
      TELEGRAM_API_ID: ${TELEGRAM_API_ID}
      TELEGRAM_API_HASH: ${TELEGRAM_API_HASH}
      TELEGRAM_STAT: 1
      TELEGRAM_LOCAL: 1
    volumes:
      # Map thư mục data của Telegram ra ổ cứng thật của bạn
      - ${TELEGRAM_LOCAL_ROOT:-./telegram-data}:/var/lib/telegram-bot-api
    ports:
      - "8081:8081"
    networks:
      - rbac_dev_net

  api:
    build:
      context: ..
      dockerfile: infra/docker/Dockerfile.dev
    container_name: rbac_api_dev
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      # Đợi Telegram bật lên mới chạy API
      telegram-api:
        condition: service_started 
    env_file:
      - ../.env.development
    environment:
      - RUN_MIGRATIONS=true
      # Ghi đè cấu hình để API gọi vào đúng Container Telegram
      - TELEGRAM_API_ROOT=http://telegram-api:8081
      - DB_HOST=postgres
      - REDIS_HOST=redis
    volumes:
      - ..:/app
      - /app/node_modules
      - dental_data_dev:/app/uploads
      # 💡 Trick siêu hay: Map chung thư mục data Telegram vào API 
      # để NestJS lấy thẳng file do Telegram tải về mà không cần qua mạng HTTP
      - ${TELEGRAM_LOCAL_ROOT:-./telegram-data}:/app/telegram-data
    ports:
      - "${PORT:-8080}:8080"
      - "9229:9229"
    networks:
      - rbac_dev_net

networks:
  rbac_dev_net:
    driver: bridge

volumes:
  pgdata_dev:
  dental_data_dev:

```

## File: infra/scripts/entrypoint.sh
```
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

```

## File: infra/scripts/healthcheck.sh
```
#!/bin/sh
# Gọi thẳng vào API Healthcheck bạn đã viết trong TestController
# Chấp nhận localhost hoặc tên container
API_URL="http://localhost:${PORT:-8080}/api/test/health"

# curl lấy HTTP status code
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL")

if [ "$STATUS" = "200" ]; then
    exit 0
else
    echo "Healthcheck failed with status: $STATUS"
    exit 1
fi

```

