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
  ApiOperation,
} from '@nestjs/swagger';

// Guards
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { Public } from '@modules/auth/infrastructure/decorators/public.decorator';

// DTOs
import { UploadCaseDto } from '../../../dental-treatment/application/dtos/upload-case.dto';

// Use Cases (Write Side)
import { UploadCaseUseCase } from '@modules/dental-treatment/application/use-cases/upload-case.use-case';

// Queries (Read Side)
import { GetCaseModelsQuery } from '@modules/dental-treatment/application/queries/get-case-models.query';
import { GetCaseDetailsQuery } from '@modules/dental-treatment/application/queries/get-case-details.query';
import { GetPatientHistoryQuery } from '@modules/dental-treatment/application/queries/get-patient-history.query';
import { ProcessMovementDataUseCase } from '@modules/dental-treatment/application/use-cases/process-movement-data.use-case';

@ApiTags('Dental 3D')
@ApiBearerAuth()
@Controller('dental')
@UseGuards(JwtAuthGuard)
export class DentalController {
  constructor(
    // Write Side
    private readonly uploadUseCase: UploadCaseUseCase,
    private readonly processMovementUseCase: ProcessMovementDataUseCase,

    // Read Side (CQRS)
    private readonly modelsQuery: GetCaseModelsQuery,
    private readonly detailsQuery: GetCaseDetailsQuery,
    private readonly historyQuery: GetPatientHistoryQuery,
  ) {}

  // =========================================================================
  // WRITE OPERATIONS
  // =========================================================================

  @Post('upload')
  @ApiOperation({ summary: 'Upload Zip file containing 3D models' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({ type: UploadCaseDto })
  @UseInterceptors(FileInterceptor('file'))
  async uploadZip(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadCaseDto,
  ) {
    return this.uploadUseCase.execute(file, dto);
  }

  @Post('upload-movement')
  @ApiOperation({ summary: 'Upload movement data (Excel/HTML)' })
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
  @UseInterceptors(FileInterceptor('file'))
  async uploadMovement(
    @UploadedFile() file: Express.Multer.File,
    @Body('caseId') caseId: string,
  ) {
    // 👇 GỌI USE CASE MỚI (Thay thế message cũ)
    return this.processMovementUseCase.execute(file, caseId);
  }

  // =========================================================================
  // READ OPERATIONS
  // =========================================================================

  @Public()
  @Get('models')
  @ApiOperation({ summary: 'Get processed 3D models for a case' })
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async listModels(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string,
  ) {
    return this.modelsQuery.execute(clientId, caseId);
  }

  @Public()
  @Get('case-details')
  @ApiOperation({ summary: 'Get detailed info of a case' })
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  @ApiQuery({ name: 'caseId', required: false })
  async getCaseDetails(
    @Query('clientId') clientId: string,
    @Query('caseId') caseId?: string,
  ) {
    return this.detailsQuery.execute(clientId, caseId);
  }

  @Get('history')
  @ApiOperation({ summary: 'Get treatment history of a patient' })
  @ApiQuery({ name: 'clientId', description: 'Patient Code' })
  async getHistory(@Query('clientId') clientId: string) {
    return this.historyQuery.execute(clientId);
  }
}
