import { Controller, Post, Get, Query, UploadedFile, UseInterceptors, UseGuards, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiTags, ApiConsumes, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { diskStorage } from 'multer';
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { UploadCaseDto } from '../dtos/upload-case.dto';

const uploadDir = 'uploads/temp';
try { fs.ensureDirSync(uploadDir); } catch (e) {}

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
  @ApiBody({ type: UploadCaseDto }) // Swagger sẽ hiển thị form đầy đủ
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto // Nhận toàn bộ thông tin qua DTO
  ) {
    // Gọi Service với file và thông tin DTO
    return this.dentalService.processZipUpload(file, dto);
  }

  @Get('models')
  async listModels(@Query('clientId') clientId: string) {
      // clientId ở đây thực chất là caseId (ID trong DB)
      return this.dentalService.listModels(clientId);
  }
}
