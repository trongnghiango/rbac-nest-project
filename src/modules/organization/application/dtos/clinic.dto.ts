import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsNumber,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger';

export class CreateClinicDto {
  @ApiProperty({ example: 'Smile Dental', description: 'Tên phòng khám' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    example: 'SMILE_HCM_01',
    description: 'Mã định danh (Unique)',
  })
  @IsString()
  @IsNotEmpty()
  clinicCode: string;

  @ApiPropertyOptional({ example: '123 Nguyen Hue, Q1, HCM' })
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional({ example: '+84901234567' })
  @IsOptional()
  @IsString()
  phoneNumber?: string;
}

export class UpdateClinicDto extends PartialType(CreateClinicDto) {}
