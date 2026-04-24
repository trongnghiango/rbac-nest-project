// src/modules/accounting/infrastructure/dtos/create-finote.request.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { CreateFinoteDto, FinoteType } from '../../application/dtos/create-finote.dto';
import { IsString, IsNotEmpty, IsNumber, IsOptional, IsEnum, IsDateString } from 'class-validator';

export class CreateFinoteRequestDto extends CreateFinoteDto {
    @ApiProperty({ description: 'Loại phiếu: INCOME (Thu) hoặc EXPENSE (Chi)', enum: FinoteType, example: 'INCOME' })
    @IsEnum(FinoteType)
    @IsNotEmpty()
    type: FinoteType;

    @ApiProperty({ description: 'Tiêu đề phiếu', example: 'Thu tiền dịch vụ tháng 4' })
    @IsString()
    @IsNotEmpty()
    title: string;

    @ApiProperty({ description: 'Số tiền', example: 15000000 })
    @IsNumber()
    @IsNotEmpty()
    amount: number;

    @ApiPropertyOptional({ description: 'ID Khách hàng (Nếu là phiếu THU)', example: 1 })
    @IsNumber()
    @IsOptional()
    organizationId?: number;

    @ApiProperty({ description: 'Phân loại chi phí / doanh thu', example: 'SERVICE_FEE' })
    @IsString()
    @IsNotEmpty()
    category: string;

    @ApiPropertyOptional({ description: 'Mô tả chi tiết' })
    @IsString()
    @IsOptional()
    description?: string;

    @ApiProperty({ description: 'Hạn chót thanh toán (ISO 8601 String)', example: '2026-05-01T00:00:00.000Z' })
    @IsDateString()
    @IsNotEmpty()
    deadlineAt: string;
}
