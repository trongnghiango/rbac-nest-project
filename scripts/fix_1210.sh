#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
ensure_dir() { mkdir -p "$@"; }

log "🛠️ FIXING DOWNLOAD ISSUE (BYPASS INTERCEPTOR)..."

# ============================================
# 1. TẠO DECORATOR "IGNORE TRANSFORM"
# ============================================
ensure_dir src/core/decorators

cat > src/core/decorators/bypass-transform.decorator.ts << 'EOF'
import { SetMetadata } from '@nestjs/common';

export const BYPASS_TRANSFORM_KEY = 'bypass_transform';
export const BypassTransform = () => SetMetadata(BYPASS_TRANSFORM_KEY, true);
EOF

# ============================================
# 2. CẬP NHẬT INTERCEPTOR
# ============================================
# Logic: Nếu gặp decorator @BypassTransform thì trả về luôn, không bọc JSON nữa.

cat > src/core/interceptors/transform-response.interceptor.ts << 'EOF'
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  StreamableFile,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<T, any> {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 1. Check xem có gắn cờ Bypass không
    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle();
    }

    // 2. Logic bọc JSON bình thường
    return next.handle().pipe(
      map((data) => {
        // Double check: Nếu data là StreamableFile thì cũng không bọc
        if (data instanceof StreamableFile) {
          return data;
        }

        return {
          success: true,
          statusCode: context.switchToHttp().getResponse().statusCode,
          message:
            this.reflector.get<string>(
              'response_message',
              context.getHandler(),
            ) || 'Success',
          result: data,
        };
      }),
    );
  }
}
EOF

# ============================================
# 3. GẮN DECORATOR VÀO CONTROLLER DOWNLOAD
# ============================================

cat > src/modules/rbac/infrastructure/controllers/rbac-manager.controller.ts << 'EOF'
import {
  Controller,
  Post,
  Get,
  UseInterceptors,
  UploadedFile,
  UseGuards,
  BadRequestException,
  Res,
  StreamableFile,
} from '@nestjs/common';
import { Response } from 'express';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '../../../auth/infrastructure/guards/jwt-auth.guard';
import { PermissionGuard } from '../guards/permission.guard';
import { Permissions } from '../decorators/permission.decorator';
import { RbacManagerService } from '../../application/services/rbac-manager.service';
import { BypassTransform } from '../../../../core/decorators/bypass-transform.decorator'; // Import mới

@Controller('rbac/data')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class RbacManagerController {
  constructor(private rbacManagerService: RbacManagerService) {}

  @Post('import')
  @Permissions('system:config')
  @UseInterceptors(FileInterceptor('file'))
  async importRbac(@UploadedFile() file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    if (!file.originalname.endsWith('.csv')) {
      throw new BadRequestException('Only .csv files are allowed');
    }

    const content = file.buffer.toString('utf-8');
    const result = await this.rbacManagerService.importFromCsv(content);

    return {
      success: true,
      message: 'RBAC data imported successfully',
      stats: result,
    };
  }

  @Get('export')
  @Permissions('system:config')
  @BypassTransform() // <--- QUAN TRỌNG: Gắn cờ để Interceptor bỏ qua
  async exportRbac(@Res({ passthrough: true }) res: Response) {
    const csvData = await this.rbacManagerService.exportToCsv();

    res.set({
      'Content-Type': 'text/csv',
      'Content-Disposition': 'attachment; filename="rbac_rules.csv"',
    });

    return new StreamableFile(Buffer.from(csvData));
  }
}
EOF

log "✅ FIX COMPLETED. PLEASE RESTART SERVER."
