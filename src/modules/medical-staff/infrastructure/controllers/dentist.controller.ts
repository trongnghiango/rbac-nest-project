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
import { IDentistRepository } from '../../domain/repositories/dentist.repository';
import {
  CreateDentistDto,
  UpdateDentistDto,
} from '../../application/dtos/dentist.dto';

@ApiTags('Medical Staff - Dentists')
@ApiBearerAuth()
@Controller('dentists')
@UseGuards(JwtAuthGuard)
export class DentistController {
  constructor(
    @Inject(IDentistRepository) private readonly repo: IDentistRepository,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Add new dentist' })
  async create(@Body() dto: CreateDentistDto) {
    return this.repo.createDentist(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List dentists (optional filter by clinic)' })
  @ApiQuery({ name: 'clinicId', required: false })
  async findAll(@Query('clinicId') clinicId?: number) {
    return this.repo.findAll(clinicId ? Number(clinicId) : undefined);
  }

  @Get(':id')
  async findOne(@Param('id') id: number) {
    return this.repo.findById(id);
  }

  @Put(':id')
  async update(@Param('id') id: number, @Body() dto: UpdateDentistDto) {
    await this.repo.update(id, dto);
    return { success: true };
  }
}
