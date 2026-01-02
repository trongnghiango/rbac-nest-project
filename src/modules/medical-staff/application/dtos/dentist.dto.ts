import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsEmail,
  IsNumber,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger';

export class CreateDentistDto {
  @ApiProperty({ example: 'Dr. Strange', description: 'Họ tên bác sĩ' })
  @IsString()
  @IsNotEmpty()
  fullName: string;

  @ApiProperty({ example: 1, description: 'ID phòng khám trực thuộc' })
  @IsNumber()
  @IsNotEmpty()
  clinicId: number;

  @ApiPropertyOptional({ example: '0909123456' })
  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @ApiPropertyOptional({ example: 'doctor@example.com' })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional({
    example: 1001,
    description: 'Liên kết với User System ID (nếu có)',
  })
  @IsOptional()
  @IsNumber()
  userId?: number;
}

export class UpdateDentistDto extends PartialType(CreateDentistDto) {}
