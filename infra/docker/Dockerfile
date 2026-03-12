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
