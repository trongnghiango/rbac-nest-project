#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "📉 DOWNGRADING UUID TO COMPATIBLE VERSION..."

# 1. Gỡ phiên bản uuid hiện tại (khả năng cao là v10+)
npm uninstall uuid @types/uuid

# 2. Cài đặt phiên bản 9.0.1 (Hỗ trợ CommonJS/require chuẩn cho NestJS)
log "📦 Installing uuid@9.0.1..."
npm install uuid@9.0.1
npm install --save-dev @types/uuid

# 3. Build lại dự án để đảm bảo mọi thứ đồng bộ
log "🔨 Rebuilding project..."
npm run build

success "✅ UUID FIXED! You can now run the production build."
echo "👉 Try running: node dist/bootstrap/main.js"