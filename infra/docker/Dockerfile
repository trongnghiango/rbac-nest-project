# ==========================================
# STAGE 1: BASE
# ==========================================
FROM node:22.15-alpine AS base
RUN apk add --no-cache libc6-compat

# ==========================================
# STAGE 2: DEPS
# ==========================================
FROM base AS deps
WORKDIR /app
# Toolchain build native (giống file Express của bạn)
RUN apk add --no-cache build-base gcc g++ autoconf automake zlib-dev libtool python3 make nasm vips-dev git linux-headers
COPY package*.json ./
RUN npm install -g node-gyp
RUN npm ci --unsafe-perm

# ==========================================
# STAGE 3: BUILDER
# ==========================================
FROM base AS builder
WORKDIR /app
COPY package*.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build
# Giữ lại dependencies (bao gồm drizzle-kit)

# ==========================================
# STAGE 4: RUNNER
# ==========================================
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Ho_Chi_Minh \
    PORT=8080

RUN apk add --no-cache dumb-init vips tzdata ca-certificates netcat-openbsd \
    && update-ca-certificates

RUN addgroup -g 1001 -S nodejs && adduser -S -u 1001 -G nodejs appuser
RUN mkdir -p /app/uploads/dental/temp /app/uploads/dental/converted /app/logs \
    && chown -R appuser:nodejs /app

# COPY NODE_MODULES (Để có lệnh drizzle-kit)
COPY --from=builder --chown=appuser:nodejs /app/node_modules ./node_modules

# COPY DIST (Chứa code JS và Schema JS)
COPY --from=builder --chown=appuser:nodejs /app/dist ./dist

# COPY package.json (Để node hiểu module)
COPY --from=builder --chown=appuser:nodejs /app/package*.json ./

# Copy Entrypoint
COPY --chown=appuser:nodejs infra/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]