import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEnum,
  IsNumber,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum ProductType {
  Aligner = 'aligner',
  Retainer = 'retainer',
}

export class CreateCaseDto {
  @ApiProperty({ example: 1, description: 'ID Bệnh nhân' })
  @IsNumber()
  @IsNotEmpty()
  patientId: number;

  @ApiPropertyOptional({ example: 1, description: 'ID Bác sĩ phụ trách' })
  @IsOptional()
  @IsNumber()
  dentistId?: number;

  @ApiProperty({ enum: ProductType, example: ProductType.Aligner })
  @IsEnum(ProductType)
  @IsNotEmpty()
  productType: ProductType;

  @ApiPropertyOptional({ example: 'Ghi chú lâm sàng...' })
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiPropertyOptional({
    example: 'ORD-12345',
    description: 'Mã đơn hàng nội bộ',
  })
  @IsOptional()
  @IsString()
  orderId?: string;
}
