import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  UseGuards,
  Inject,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '@modules/auth/infrastructure/guards/jwt-auth.guard';
import { IClinicRepository } from '../../domain/repositories/clinic.repository';
import {
  CreateClinicDto,
  UpdateClinicDto,
} from '../../application/dtos/clinic.dto';

@ApiTags('Organization - Clinics')
@ApiBearerAuth()
@Controller('clinics')
@UseGuards(JwtAuthGuard)
export class ClinicController {
  constructor(
    @Inject(IClinicRepository) private readonly repo: IClinicRepository,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create new clinic' })
  async create(@Body() dto: CreateClinicDto) {
    return this.repo.createClinic(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List all clinics' })
  async findAll() {
    return this.repo.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get clinic details' })
  async findOne(@Param('id') id: number) {
    return this.repo.findById(id);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update clinic info' })
  async update(@Param('id') id: number, @Body() dto: UpdateClinicDto) {
    await this.repo.update(id, dto);
    return { success: true, message: 'Updated successfully' };
  }
}
