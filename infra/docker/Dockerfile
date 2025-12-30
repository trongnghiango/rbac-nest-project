# ==========================================
# STAGE 1: BASE (Chuẩn bị môi trường chung)
# ==========================================
FROM node:22-alpine AS base
# Cài đặt libc6-compat để tương thích thư viện native (quan trọng cho worker 3D)
RUN apk add --no-cache libc6-compat

# ==========================================
# STAGE 2: DEPENDENCIES (Cài node_modules)
# ==========================================
FROM base AS deps
WORKDIR /app
# Cài python3, make, g++ để build native modules (sharp, gltf-pipeline, etc.)
RUN apk add --no-cache python3 make g++ git

COPY package*.json ./
# Dùng cache mount để tăng tốc độ npm install cho các lần build sau
RUN --mount=type=cache,target=/root/.npm \
    npm ci

# ==========================================
# STAGE 3: BUILDER (Biên dịch TypeScript)
# ==========================================
FROM base AS builder
WORKDIR /app
COPY package*.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build NestJS
RUN npm run build

# Sau khi build xong, prune để chỉ giữ lại production dependencies
# Lưu ý: Cần giữ lại các tool CLI dùng trong Runtime (như drizzle-kit nếu chạy push)
# Nếu drizzle-kit nằm ở devDependencies, bạn nên chuyển nó sang dependencies
# hoặc bỏ qua bước prune này nếu chấp nhận image nặng hơn chút.
# Ở đây mình giả định bạn muốn tối ưu dung lượng:
RUN npm prune --production

# ==========================================
# STAGE 4: RUNNER (Chạy ứng dụng)
# ==========================================
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Ho_Chi_Minh \
    PORT=8080

# Cài dumb-init (PID 1 handling) và các thư viện runtime cần thiết
# vips: hỗ trợ xử lý ảnh nếu sharp dùng global libvips
RUN apk add --no-cache dumb-init vips tzdata ca-certificates \
    && update-ca-certificates

# Tạo user để không chạy dưới quyền root (Security Best Practice)
RUN addgroup -g 1001 -S nodejs && adduser -S -u 1001 -G nodejs appuser

# Tạo các thư mục cần thiết và gán quyền
RUN mkdir -p /app/uploads/dental/temp \
    /app/uploads/dental/converted \
    /app/logs \
    && chown -R appuser:nodejs /app

# Copy artifacts từ các stage trước
COPY --from=deps /app/node_modules ./node_modules
# Nếu bước prune ở builder xóa mất native binary, hãy copy lại từ deps hoặc builder (sau prune)
# Tốt nhất: Copy node_modules từ builder vì nó đã được prune (hoặc giữ nguyên nếu bỏ prune)
COPY --from=builder --chown=appuser:nodejs /app/dist ./dist
COPY --from=builder --chown=appuser:nodejs /app/package*.json ./
COPY --from=builder --chown=appuser:nodejs /app/drizzle.config.ts ./
COPY --from=builder --chown=appuser:nodejs /app/src/database/schema ./src/database/schema

# Copy scripts
COPY --chown=appuser:nodejs infra/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER appuser

EXPOSE 8080

# Sử dụng dumb-init làm entrypoint chính để quản lý process con
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]