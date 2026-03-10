## File: infra/docker/Dockerfile.dev
```
FROM node:22-alpine
RUN apk add --no-cache python3 make g++ git openssl libc6-compat
WORKDIR /app
ENV NODE_ENV=development
# Port mặc định cho NestJS Dev
EXPOSE 8080
COPY infra/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

```

## File: infra/docker/Dockerfile
```
# ---- Stage 1: Builder ----
FROM node:22-alpine AS builder
RUN apk add --no-cache python3 make g++ git openssl libc6-compat
WORKDIR /app
COPY package*.json ./
COPY tsconfig*.json ./
COPY nest-cli.json ./
COPY drizzle.config.ts ./
RUN npm ci
COPY . .
RUN npm run build

# ---- Stage 2: Production runtime ----
FROM node:22-alpine AS production
RUN apk add --no-cache vips tzdata ca-certificates dumb-init libc6-compat \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

ENV TZ=Asia/Ho_Chi_Minh \
    NODE_ENV=production \
    PORT=8080

RUN addgroup -g 1001 -S appgroup && adduser -S -u 1001 -G appgroup appuser
WORKDIR /app

RUN mkdir -p /app/uploads/dental/temp /app/uploads/dental/converted /app/logs /app/tmp \
    && chown -R appuser:appgroup /app

# Copy artifacts
COPY --chown=appuser:appgroup --from=builder /app/dist ./dist
# Lưu ý: Ở bản Prod này, chúng ta copy toàn bộ node_modules (bao gồm devDeps)
# để drizzle-kit có thể biên dịch file .ts khi chạy lệnh push
COPY --chown=appuser:appgroup --from=builder /app/node_modules ./node_modules
COPY --chown=appuser:appgroup package*.json ./
COPY --chown=appuser:appgroup drizzle.config.ts ./
COPY --chown=appuser:appgroup src/database/schema ./src/database/schema

COPY --chown=appuser:appgroup infra/scripts/ ./
RUN chmod +x ./*.sh

EXPOSE 8080
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
USER appuser
CMD ["./entrypoint.sh"]

```

## File: infra/scripts/entrypoint.sh
```
#!/bin/sh
set -e

echo "⌛ Đang kiểm tra kết nối Database..."
# Chờ cho đến khi Postgres thực sự chấp nhận kết nối
until nc -z $DB_HOST 5432; do
  echo "Postgres chưa sẵn sàng - đang chờ..."
  sleep 2
done

echo "✅ Database đã mở cổng 5432!"

# Tạo DATABASE_URL
export DATABASE_URL="postgres://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}"

if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "🚀 Bắt đầu chạy Migrations (Drizzle)..."
    # Thử lại 3 lần nếu lỗi (tránh việc Postgres đang bận khởi tạo nội bộ)
    MAX_RETRIES=5
    COUNT=0
    until npx drizzle-kit push --force || [ $COUNT -eq $MAX_RETRIES ]; do
        COUNT=$((COUNT + 1))
        echo "Migration thất bại lần $COUNT. Thử lại sau 3 giây..."
        sleep 3
    done

    if [ $COUNT -eq $MAX_RETRIES ]; then
        echo "❌ Migration thất bại hoàn toàn sau $MAX_RETRIES lần thử!"
        exit 1
    fi
    echo "✅ Migrations hoàn tất thành công!"
fi

echo "🚀 Khởi động ứng dụng NestJS..."
exec node dist/src/bootstrap/main.js

```

## File: infra/scripts/healthcheck.sh
```
#!/bin/sh
# Kiểm tra đơn giản qua cổng PORT
nc -z localhost ${PORT:-8080} || exit 1

```

## File: infra/docker-compose.yml
```
services:
  postgres:
    image: postgres:15-alpine
    container_name: rbac_db_dev
    environment:
      - POSTGRES_USER=${DB_USERNAME:-postgres}
      - POSTGRES_PASSWORD=${DB_PASSWORD:-postgres}
      - POSTGRES_DB=${DB_NAME:-rbac_system}
    ports:
      - "5432:5432"
    volumes:
      - pgdata_dev:/var/lib/postgresql/data
    networks:
      - rbac_dev_net

  redis:
    image: redis:alpine
    container_name: rbac_redis_dev
    ports:
      - "6379:6379"
    networks:
      - rbac_dev_net

  api:
    build:
      context: ..
      dockerfile: infra/docker/Dockerfile.dev
    container_name: rbac_api_dev
    depends_on:
      - postgres
      - redis
    env_file:
      - ../.env
    environment:
      - DB_HOST=postgres
      - REDIS_HOST=redis
      - RUN_MIGRATIONS=true
    volumes:
      - ..:/app
      - /app/node_modules
    ports:
      - "8080:8080"
    networks:
      - rbac_dev_net

networks:
  rbac_dev_net:
    driver: bridge

volumes:
  pgdata_dev:

```

## File: infra/docker-compose.prod.yml
```
services:
  postgres:
    image: postgres:15-alpine
    container_name: rbac_postgres_prod
    restart: always
    env_file:
      - ../.env.production
    environment:
      - POSTGRES_USER=${DB_USERNAME:-postgres}
      - POSTGRES_PASSWORD=${DB_PASSWORD:-postgres}
      - POSTGRES_DB=${DB_NAME:-rbac_system}
    volumes:
      - pgdata_prod:/var/lib/postgresql/data
    networks:
      - rbac_prod_net
    healthcheck:
      # Sửa lỗi: Thêm cờ -d ${DB_NAME} để không tìm database "admin"
      test: ["CMD-SHELL", "pg_isready -U ${DB_USERNAME:-postgres} -d ${DB_NAME:-rbac_system}"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    container_name: rbac_redis_prod
    restart: always
    networks:
      - rbac_prod_net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

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
    env_file:
      - ../.env.production
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - REDIS_HOST=redis
      - RUN_MIGRATIONS=true
      - RUN_SEEDS=true
      - APP_URL=${APP_URL:-http://localhost:8080}
    volumes:
      - dental_data:/app/uploads
      - api_logs:/app/logs
    ports:
      - "8080:8080"
    networks:
      - rbac_prod_net

networks:
  rbac_prod_net:
    driver: bridge

volumes:
  pgdata_prod:
  dental_data:
  api_logs:

```

