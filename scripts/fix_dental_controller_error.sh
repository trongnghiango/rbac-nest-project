#!/bin/bash

# Màu sắc
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

log "🚑 FIXING FS-EXTRA IMPORT ERROR IN DENTAL CONTROLLER..."

# Ghi đè lại file controller với cách import đúng
cat > src/modules/dental/infrastructure/controllers/dental.controller.ts << 'EOF'
import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { diskStorage } from 'multer';
import path from 'path';
// ✅ FIX: Import toàn bộ namespace thay vì default import
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';

// Cấu hình Multer lưu tạm
const uploadDir = 'uploads/temp';

// Đảm bảo thư mục tồn tại (Sync để chạy 1 lần lúc khởi tạo file)
try {
  fs.ensureDirSync(uploadDir);
} catch (error) {
  console.error('Error creating temp upload dir:', error);
}

const storage = diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

@ApiTags('Dental 3D')
@ApiBearerAuth()
@Controller('dental')
@UseGuards(JwtAuthGuard)
export class DentalController {
  constructor(private readonly dentalService: DentalService) {}

  @Post('upload')
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary' },
        clientId: { type: 'string' }
      },
    },
  })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body('clientId') clientId: string
  ) {
    // Fallback nếu clientId không có trong body (ví dụ test qua Swagger cũ)
    const finalClientId = clientId || 'default-client';
    return this.dentalService.processZipUpload(file, finalClientId);
  }

  @Get('models')
  async listModels(@Query('clientId') clientId: string) {
      return this.dentalService.listModels(clientId || 'default-client');
  }
}
EOF

success "✅ FIXED! 'fs-extra' is now imported correctly using 'import * as fs'."
echo "👉 NestJS should restart automatically and compile successfully."