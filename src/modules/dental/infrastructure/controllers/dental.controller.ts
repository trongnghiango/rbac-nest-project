import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { diskStorage } from 'multer';
import path from 'path';
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';

// Cấu hình Multer lưu tạm
const uploadDir = 'uploads/temp';

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
    const finalClientId = clientId || 'default-client';
    const result = await this.dentalService.processZipUpload(file, finalClientId);

    // Trả về object chuẩn, Interceptor sẽ lo phần wrap success/statusCode
    return {
        message: 'File uploaded and processing started',
        jobId: result.jobId,
        stats: result.stats
    };
  }

  @Get('models')
  async listModels(@Query('clientId') clientId: string) {
      const finalClientId = clientId || 'default-client';
      const models = await this.dentalService.listModels(finalClientId);

      // ✅ FIX: Interceptor global của chúng ta (TransformResponseInterceptor)
      // sẽ tự động bọc kết quả này vào { success: true, statusCode: 200, result: ... }
      // Nhưng nếu bạn muốn cấu trúc Metadata riêng biệt như hình mẫu, ta có thể return object tùy chỉnh.

      // Tuy nhiên, để nhất quán với toàn bộ hệ thống, ta nên return data raw,
      // và để Interceptor lo phần format chung.

      // Nếu bạn muốn override message mặc định 'Success':
      // (Cần dùng decorator @ResponseMessage('Successfully listed models.') nhưng ở đây ta return thẳng)

      return models;
  }
}
