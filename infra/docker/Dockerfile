# STAGE 1: BASE
FROM node:22.15-alpine AS base
RUN apk add --no-cache libc6-compat
RUN corepack enable && corepack prepare pnpm@latest --activate
# 👉 Tắt cảnh báo update pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

# STAGE 2: BUILDER (Gom code bằng Webpack)
FROM base AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
# 👉 Ép pnpm chạy script C++ để cài đặt thành công mọi devDeps
RUN pnpm config set ignore-scripts false && pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build 

# STAGE 3: PROD_DEPS (Chỉ cài thư viện Production)
FROM base AS prod_deps
WORKDIR /app
# Phải có compiler C++ để build bcrypt
RUN apk add --no-cache build-base python3 make
COPY package.json pnpm-lock.yaml* ./
# 👉 FIX LỖI CRITICAL: Bắt buộc set ignore-scripts false để bcrypt biên dịch C++
RUN pnpm config set ignore-scripts false && pnpm install --prod --frozen-lockfile

# STAGE 4: RUNNER (Final Image)
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Ho_Chi_Minh \
    PORT=8080

RUN apk add --no-cache dumb-init vips tzdata ca-certificates curl postgresql-client \
    && update-ca-certificates

RUN addgroup -g 1001 -S nodejs && adduser -S -u 1001 -G nodejs appuser
RUN mkdir -p /app/uploads/dental/temp /app/uploads/dental/converted /app/logs \
    && chown -R appuser:nodejs /app

COPY --from=prod_deps --chown=appuser:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:nodejs /app/dist ./dist
COPY --from=builder --chown=appuser:nodejs /app/src/database ./src/database
COPY --from=builder --chown=appuser:nodejs /app/drizzle.config.ts ./
COPY --from=builder --chown=appuser:nodejs /app/package.json ./
COPY --from=builder --chown=appuser:nodejs /app/tsconfig.json ./

COPY infra/scripts/entrypoint.sh /entrypoint.sh
COPY infra/scripts/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh && chown appuser:nodejs /entrypoint.sh /healthcheck.sh

USER appuser
EXPOSE 8080

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]
