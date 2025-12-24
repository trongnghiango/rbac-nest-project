import {
  Controller,
  Post,
  Get,
  Query,
  UploadedFile,
  UseInterceptors,
  UseGuards,
  Body,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiConsumes,
  ApiBody,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { diskStorage } from 'multer';
import * as fs from 'fs-extra';
import { DentalService } from '../../application/services/dental.service';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { UploadCaseDto } from '../dtos/upload-case.dto';
import { Public } from '@modules/auth/infrastructure/decorators/public.decorator';

const uploadDir = 'uploads/temp';
try {
  fs.ensureDirSync(uploadDir);
} catch (e) {}

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
  @ApiBody({ type: UploadCaseDto })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto,
  ) {
    return this.dentalService.processZipUpload(file, dto);
  }

  // ✅ NEW: API Upload Excel Data
  @Post('upload-movement')
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary' },
        caseId: { type: 'string' },
      },
    },
  })
  @UseInterceptors(FileInterceptor('file', { storage }))
  async uploadMovement(
    @UploadedFile() file: Express.Multer.File,
    @Body('caseId') caseId: string,
  ) {
    return this.dentalService.processMovementExcel(file, caseId);
  }

  @Public()
  @Get('models')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async listModels(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string,
  ) {
    return this.dentalService.listModels(clientId, caseId);
  }

  @Public()
  @Get('case-details')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async getCaseDetails(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string,
  ) {
    return this.dentalService.getCaseDetails(clientId, caseId);
  }

  @Get('history')
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  async getHistory(@Query('clientId') clientId: string) {
    return this.dentalService.getHistory(clientId);
  }
}
