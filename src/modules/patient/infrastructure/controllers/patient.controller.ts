import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Query,
  UseGuards,
  Inject,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { IPatientRepository } from '../../domain/repositories/patient.repository';
import {
  CreatePatientDto,
  UpdatePatientDto,
} from '../../application/dtos/patient.dto';

@ApiTags('Patient - Management')
@ApiBearerAuth()
@Controller('patients')
@UseGuards(JwtAuthGuard)
export class PatientController {
  constructor(
    @Inject(IPatientRepository) private readonly repo: IPatientRepository,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create new patient' })
  async create(@Body() dto: CreatePatientDto) {
    return this.repo.createPatient(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List patients (optional filter by clinic)' })
  @ApiQuery({ name: 'clinicId', required: false })
  async findAll(@Query('clinicId') clinicId?: number) {
    return this.repo.findAll(clinicId ? Number(clinicId) : undefined);
  }

  @Get(':id')
  async findOne(@Param('id') id: number) {
    return this.repo.findById(id);
  }

  @Put(':id')
  async update(@Param('id') id: number, @Body() dto: UpdatePatientDto) {
    await this.repo.update(id, dto);
    return { success: true };
  }
}
